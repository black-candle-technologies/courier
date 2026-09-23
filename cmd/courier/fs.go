// Forward-secrecy session management (issue #50).
package main

import (
	"fmt"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
)

func cmdFS(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier fs <status|start|on|off|rekey|forget|require> [peer]")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	c := client.New(cfg)
	switch args[0] {
	case "status":
		var peer string
		if len(args) > 1 {
			peer = args[1]
		}
		return cmdFSStatus(c, cfg, peer)
	case "start":
		if len(args) < 2 {
			return fmt.Errorf("usage: courier fs start <peer>")
		}
		if err := c.FSStart(args[1]); err != nil {
			return err
		}
		fmt.Println("forward-secrecy handshake initiated. The first message to this peer still goes over legacy encryption; later messages use forward secrecy once they accept.")
		return nil
	case "on":
		if len(args) < 2 {
			return fmt.Errorf("usage: courier fs on <peer>")
		}
		if err := c.FSSetPeerMode(args[1], "on"); err != nil {
			return err
		}
		fmt.Println("forward secrecy enabled for this peer; handshake initiated.")
		return nil
	case "off":
		if len(args) < 2 {
			return fmt.Errorf("usage: courier fs off <peer>")
		}
		if err := c.FSSetPeerMode(args[1], "off"); err != nil {
			return err
		}
		fmt.Println("forward secrecy disabled for this peer; any session keys were erased. Messages fall back to legacy encryption.")
		if required, rerr := c.FSRequireForPeer(args[1]); rerr == nil && required {
			fmt.Println("note: `courier fs require` is still set for this peer, so sends will now FAIL until you run `courier fs require <peer> off` or re-establish a session.")
		}
		return nil
	case "rekey":
		if len(args) < 2 {
			return fmt.Errorf("usage: courier fs rekey <peer>")
		}
		if err := c.FSRekey(args[1]); err != nil {
			return err
		}
		fmt.Println("the next message to this peer rotates the forward-secrecy ratchet.")
		return nil
	case "forget":
		if len(args) < 2 {
			return fmt.Errorf("usage: courier fs forget <peer>")
		}
		if err := c.FSForget(args[1]); err != nil {
			return err
		}
		fmt.Println("forward-secrecy session erased for this peer (and disabled, so it won't silently re-establish).")
		if required, rerr := c.FSRequireForPeer(args[1]); rerr == nil && required {
			fmt.Println("note: `courier fs require` is still set for this peer, so sends will now FAIL until you run `courier fs require <peer> off` or re-establish a session.")
		}
		return nil
	case "require":
		// Issue #110: per-contact fail-closed policy.
		if len(args) < 2 {
			return fmt.Errorf("usage: courier fs require <peer> [on|off]")
		}
		want := true
		if len(args) > 2 {
			switch args[2] {
			case "on":
				want = true
			case "off":
				want = false
			default:
				return fmt.Errorf("usage: courier fs require <peer> [on|off]")
			}
		}
		if err := c.FSSetRequireFS(args[1], want); err != nil {
			return err
		}
		if want {
			fmt.Println("forward secrecy REQUIRED for this peer: sends now fail closed unless an FS session is established (no silent legacy fallback).")
			fmt.Println("if no session exists yet, run `courier fs on <peer>` or `courier fs start <peer>` first — until the handshake completes, sends will fail.")
		} else {
			fmt.Println("forward-secrecy requirement lifted for this peer; sends fall back to legacy encryption as before (fail-open default).")
		}
		return nil
	default:
		return fmt.Errorf("unknown fs subcommand %q (status|start|on|off|rekey|forget|require)", args[0])
	}
}

func cmdFSStatus(c *client.Client, cfg *client.Config, peer string) error {
	infos, err := c.FSStatus(peer)
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		if peer != "" {
			fmt.Println("no forward-secrecy session with this peer (legacy encryption in use).")
			// Issue #110: still report the fail-closed policy and any
			// pinned capability — they exist independently of sessions.
			if required, rerr := c.FSRequireForPeer(peer); rerr == nil && required {
				fmt.Println("forward secrecy is REQUIRED for this peer: sends fail closed until a session is established.")
			}
			if pinnedAt, perr := c.FSPinnedAt(peer); perr == nil && pinnedAt > 0 {
				fmt.Printf("capability: pinned (peer proved FS support %s).\n", fsTimeAgo(pinnedAt))
			}
		} else {
			fmt.Println("no forward-secrecy sessions. New DMs use forward secrecy automatically once a peer's client advertises support.")
		}
		return nil
	}
	for _, in := range infos {
		name := fsPeerLabel(cfg, in.Peer)
		state := "handshake pending"
		if in.Established {
			state = "established"
		}
		role := "responder"
		if in.Initiator {
			role = "initiator"
		}
		fmt.Printf("%s\n  state: %s (%s), mode: %s\n  suite: %s\n  messages: %d sent, %d received\n  last rotation: %s\n",
			name, state, role, in.Mode, in.Suite, in.MsgsSent, in.MsgsRecvd,
			fsTimeAgo(in.LastRotateAt))
		// Issue #110: policy, pin, and downgrade state.
		if in.RequireFS {
			fmt.Println("  require-fs: yes (sends fail closed without an established session)")
		}
		if in.Pinned {
			fmt.Println("  capability: pinned (peer proved FS support before)")
		}
		if in.DowngradeSuspected {
			fmt.Printf("  ⚠ DOWNGRADE SUSPECTED since %s: peer previously used FS, now legacy-only. Run `courier fs start <peer>` to retry the handshake.\n",
				fsTimeAgo(in.DowngradeSince))
		}
	}
	return nil
}

func fsPeerLabel(cfg *client.Config, address string) string {
	for name, addr := range cfg.Contacts {
		if addr == address {
			return fmt.Sprintf("%s (%s)", name, address)
		}
	}
	if len(address) > 24 {
		return address[:24] + "…"
	}
	return address
}

func fsTimeAgo(ts int64) string {
	if ts == 0 {
		return "never"
	}
	d := time.Since(time.Unix(ts, 0))
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
