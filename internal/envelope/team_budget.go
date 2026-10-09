package envelope

import "reflect"

// teamEncodedSize preflights the sealed, acyclic v1 structs without creating a
// serialized copy. It counts encoding/json's exact representation (including
// HTML escaping), preserving the existing object/chain byte-budget contract.
// Every addition is checked by subtraction, before walking or allocating output.
// Only these concrete types may reach the walker: no custom marshalers, maps,
// interfaces, recursive pointers, omitempty, or arbitrary caller-defined types.
func teamEncodedSize(v any, l TeamLimits, remaining int) (int, error) {
	if e := l.Validate(); e != nil {
		return 0, e
	}
	switch v.(type) {
	case TeamRoster, *TeamRoster, TeamInvitation, *TeamInvitation,
		TeamAcceptance, *TeamAcceptance, TeamOwnerTransition, *TeamOwnerTransition:
	default:
		return 0, ErrTeamWire
	}
	cap := l.MaxObjectBytes
	if remaining < cap {
		cap = remaining
	}
	if cap < 0 {
		return 0, ErrTeamLimit
	}
	b := teamSizeBudget{remaining: cap, limits: l}
	x := reflect.ValueOf(v)
	if x.Kind() == reflect.Pointer {
		if x.IsNil() {
			return 0, ErrTeamWire
		}
		x = x.Elem()
	}
	if e := b.value(x); e != nil {
		return 0, e
	}
	return cap - b.remaining, nil
}

type teamSizeBudget struct {
	remaining int
	limits    TeamLimits
}

func (b *teamSizeBudget) add(n int) error {
	if n < 0 || n > b.remaining {
		return ErrTeamLimit
	}
	b.remaining -= n
	return nil
}
func (b *teamSizeBudget) string(s string) error {
	if len(s) > b.limits.MaxStringBytes {
		return ErrTeamLimit
	}
	if e := b.add(2); e != nil {
		return e
	}
	// Reject a long value in O(1) before scanning it. Count escapes separately
	// so no len*escape-factor multiplication can overflow.
	if e := b.add(len(s)); e != nil {
		return e
	}
	for i := 0; i < len(s); i++ {
		n := 0
		switch c := s[i]; {
		case c < 0x20 || c > 0x7e:
			return ErrTeamWire
		case c == '<' || c == '>' || c == '&':
			n = 5
		case c == '"' || c == '\\':
			n = 1
		}
		if e := b.add(n); e != nil {
			return e
		}
	}
	return nil
}
func (b *teamSizeBudget) fields(v reflect.Value, first *bool) error {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := t.Field(i)
		x := v.Field(i)
		if f.Anonymous {
			if e := b.fields(x, first); e != nil {
				return e
			}
			continue
		}
		if !*first {
			if e := b.add(1); e != nil {
				return e
			}
		}
		*first = false
		if e := b.string(f.Tag.Get("json")); e != nil {
			return e
		}
		if e := b.add(1); e != nil {
			return e
		}
		if f.Name == "Members" && x.Len() > b.limits.MaxMembers {
			return ErrTeamLimit
		}
		if e := b.value(x); e != nil {
			return e
		}
	}
	return nil
}
func (b *teamSizeBudget) value(v reflect.Value) error {
	switch v.Kind() {
	case reflect.String:
		return b.string(v.String())
	case reflect.Pointer:
		if v.IsNil() {
			return b.add(4)
		}
		return b.value(v.Elem())
	case reflect.Struct:
		if e := b.add(2); e != nil {
			return e
		}
		first := true
		return b.fields(v, &first)
	case reflect.Slice:
		if v.Len() > b.limits.MaxArrayItems {
			return ErrTeamLimit
		}
		if v.IsNil() {
			return b.add(4)
		}
		if e := b.add(2); e != nil {
			return e
		}
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				if e := b.add(1); e != nil {
					return e
				}
			}
			if e := b.value(v.Index(i)); e != nil {
				return e
			}
		}
		return nil
	default:
		return ErrTeamWire
	}
}
