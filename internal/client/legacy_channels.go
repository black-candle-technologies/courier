package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// The cc:2 discriminator stays reserved after channel retirement. In particular,
// join and rekey frames carry secrets and must never degrade into ordinary chat.
func isLegacyChannelPayload(plain []byte) bool {
	var p struct {
		Magic int    `json:"cc"`
		Type  string `json:"t"`
	}
	if json.Unmarshal(plain, &p) != nil || p.Magic != 2 {
		return false
	}
	switch p.Type {
	case "join-request", "join-accept", "msg", "rekey", "leave":
		return true
	}
	return false
}

var legacyChannelWarnings sync.Map // archive paths already warned about in this process

// Warn without opening or modifying sensitive legacy history. Retirement is an
// explicit operator action because the file also holds non-expiring user data.
func (s Context) warnLegacyChannels() error {
	p, err := s.configPath()
	if err != nil {
		return err
	}
	p = filepath.Join(filepath.Dir(p), "channels.json")
	if _, err = os.Lstat(p); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if _, loaded := legacyChannelWarnings.LoadOrStore(p, struct{}{}); loaded {
		return nil
	}
	fmt.Fprintln(os.Stderr, "warning: retired channels.json still contains channel history and secrets; see https://github.com/black-candle-technologies/courier/blob/main/docs/legacy-channel-retirement.md for explicit export and cleanup. Courier does not migrate or delete it automatically.")
	return nil
}
