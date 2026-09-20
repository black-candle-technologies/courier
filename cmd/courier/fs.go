// Forward-secrecy session management (issue #50).
package main

import (
	"fmt"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
)

func cmdFS(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: courier fs <status|start|on|off|rekey|forget> [peer]")
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
		return nil
	default:
		return fmt.Errorf("unknown fs subcommand %q (status|start|on|off|rekey|forget)", args[0])
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
		fmt.Printf("%s\n  state: %s (%s), mode: %s\n  messages: %d sent, %d received\n  last rotation: %s\n",
			name, state, role, in.Mode, in.MsgsSent, in.MsgsRecvd,
			fsTimeAgo(in.LastRotateAt))
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
