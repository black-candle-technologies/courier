package envelope

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"
)

// TeamLimits are caller-selected resource budgets, never implicit release policy.
// Every field is mandatory. InvitationLifetimeSeconds must not exceed 24 hours.
// MaxChainBytes bounds the sum of snapshots, certificates and consent objects.
type TeamLimits struct {
	MaxObjectBytes            int
	MaxStringBytes            int
	MaxArrayItems             int
	MaxMembers                int
	MaxChainObjects           int
	MaxChainBytes             int
	InvitationLifetimeSeconds int64
}

func (l TeamLimits) Validate() error {
	if l.MaxObjectBytes < 1 || l.MaxStringBytes < 1 || l.MaxStringBytes > l.MaxObjectBytes || l.MaxArrayItems < 2 || l.MaxMembers < 1 || l.MaxMembers > l.MaxArrayItems || l.MaxChainObjects < 1 || l.MaxChainBytes < l.MaxObjectBytes || l.InvitationLifetimeSeconds < 1 || l.InvitationLifetimeSeconds > 86400 {
		return fmt.Errorf("%w: resource budgets", ErrTeamLimit)
	}
	return nil
}

// CanonicalTeamJSON implements RFC 8785 on the deliberately restricted v1
// grammar: printable ASCII strings, null, objects and arrays. JSON numbers and
// booleans are forbidden; counters are canonical decimal strings. ASCII key
// ordering equals UTF-16 ordering. This is NOT a general purpose JCS encoder.
// Escaped representations of accepted ASCII are accepted; duplicate decoded
// keys, non-ASCII (including lone surrogates), controls and trailing data fail.
func CanonicalTeamJSON(raw []byte, limits TeamLimits) ([]byte, error) {
	v, err := teamJSON(raw, limits)
	if err != nil {
		return nil, err
	}
	return appendTeamJSON(nil, v), nil
}

func teamJSON(raw []byte, l TeamLimits) (any, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	if len(raw) > l.MaxObjectBytes {
		return nil, ErrTeamLimit
	}
	if !utf8.Valid(raw) {
		return nil, ErrTeamWire
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readTeamJSON(d, l, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrTeamWire
	}
	return v, nil
}

func readTeamJSON(d *json.Decoder, l TeamLimits, depth int) (any, error) {
	// Wire schema depth is at most four; eight permits wrappers without allowing
	// attacker-controlled recursive stack growth. This is a grammar restriction.
	if depth > 8 {
		return nil, ErrTeamWire
	}
	t, err := d.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: JSON", ErrTeamWire)
	}
	switch x := t.(type) {
	case nil:
		return nil, nil
	case string:
		if len(x) > l.MaxStringBytes {
			return nil, ErrTeamLimit
		}
		for _, c := range x {
			if c < 0x20 || c > 0x7e {
				return nil, ErrTeamWire
			}
		}
		return x, nil
	case json.Delim:
		switch x {
		case '{':
			obj := map[string]any{}
			for d.More() {
				k, err := readTeamJSON(d, l, depth+1)
				if err != nil {
					return nil, err
				}
				key, ok := k.(string)
				if !ok {
					return nil, ErrTeamWire
				}
				if _, exists := obj[key]; exists {
					return nil, fmt.Errorf("%w: duplicate field", ErrTeamWire)
				}
				// No v1 object has more than 32 fields.
				if len(obj) >= 32 {
					return nil, ErrTeamWire
				}
				obj[key], err = readTeamJSON(d, l, depth+1)
				if err != nil {
					return nil, err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrTeamWire
			}
			return obj, nil
		case '[':
			arr := []any{}
			for d.More() {
				if len(arr) >= l.MaxArrayItems {
					return nil, ErrTeamLimit
				}
				v, err := readTeamJSON(d, l, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrTeamWire
			}
			return arr, nil
		}
	}
	return nil, ErrTeamWire
}

func appendTeamJSON(out []byte, v any) []byte {
	switch x := v.(type) {
	case nil:
		return append(out, "null"...)
	case string:
		out = append(out, '"')
		for i := 0; i < len(x); i++ {
			if x[i] == '"' || x[i] == '\\' {
				out = append(out, '\\')
			}
			out = append(out, x[i])
		}
		return append(out, '"')
	case []any:
		out = append(out, '[')
		for i, v := range x {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendTeamJSON(out, v)
		}
		return append(out, ']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out = append(out, '{')
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendTeamJSON(out, k)
			out = append(out, ':')
			out = appendTeamJSON(out, x[k])
		}
		return append(out, '}')
	default:
		panic("team JSON internal type")
	}
}

func parseTeam(raw []byte, dst any, l TeamLimits) error {
	canonical, err := CanonicalTeamJSON(raw, l)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if err = d.Decode(dst); err != nil {
		return fmt.Errorf("%w: schema", ErrTeamWire)
	}
	// Exact round trip detects missing required fields, null scalar fields and
	// encoding/json's case-insensitive field matching. No wire field is optional.
	encoded, err := json.Marshal(dst)
	if err != nil {
		return ErrTeamWire
	}
	round, err := CanonicalTeamJSON(encoded, l)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, round) {
		return fmt.Errorf("%w: missing or mismatched fields", ErrTeamWire)
	}
	return nil
}
