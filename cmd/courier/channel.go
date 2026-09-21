package main

// OOB-code private channels CLI (issue #48, phase 2).

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
)

func cmdChannel(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: courier channel <create|invite|join|send|inbox|list|remove|leave>")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	switch args[0] {
	case "create":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier channel create <name>")
		}
		ch, err := cl.ChannelCreate(args[1])
		if err != nil {
			return err
		}
		fmt.Printf("channel %q created: %s\n", ch.Name, ch.ID)
		fmt.Println("Invite members with: courier channel invite " + ch.ID)
	case "invite":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier channel invite <channel-id>")
		}
		code, err := cl.ChannelInvite(args[1])
		if err != nil {
			return err
		}
		fmt.Println("One-time join code (valid 24h). Send it to the invitee over a")
		fmt.Println("separate channel — whoever holds it can join:")
		fmt.Printf("\n  %s\n\n", code)
		fmt.Printf("They join with: courier channel join <your-address-or-contact> %s\n", code)
	case "join":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier channel join <inviter> <code>")
		}
		fmt.Println("Sending join request; waiting for the inviter's agent (up to 60s)...")
		if err := cl.ChannelJoin(args[1], args[2]); err != nil {
			return err
		}
		fmt.Println("Joined. The inviter is now marked verified (out-of-band code).")
	case "send":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier channel send <channel-id> <message>")
		}
		if err := cl.ChannelSend(args[1], args[2]); err != nil {
			return err
		}
		fmt.Println("sent.")
	case "inbox":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier channel inbox <channel-id>")
		}
		msgs, err := cl.ChannelMessages(args[1])
		if err != nil {
			return err
		}
		if len(msgs) == 0 {
			fmt.Println("no channel messages yet.")
			return nil
		}
		for _, m := range msgs {
			who := shortAddr(m.From)
			if m.From == cfg.Address {
				who = "you"
			}
			fmt.Printf("[%s] %s: %s\n",
				time.Unix(m.SentAt, 0).Format("15:04"), who, m.Body)
		}
	case "list":
		chs, err := cl.ChannelList()
		if err != nil {
			return err
		}
		if len(chs) == 0 {
			fmt.Println("no private channels yet. Create one with: courier channel create <name>")
			return nil
		}
		sort.Slice(chs, func(i, j int) bool { return chs[i].Name < chs[j].Name })
		for _, ch := range chs {
			role := "member"
			if ch.Admin == cfg.Address {
				role = "admin"
			}
			fmt.Printf("%-20s %-34s %2d members  %s\n", ch.Name, ch.ID, len(ch.Roster), role)
		}
	case "remove":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier channel remove <channel-id> <address|contact>")
		}
		if err := cl.ChannelRemoveMember(args[1], args[2]); err != nil {
			return err
		}
		fmt.Println("member removed; channel key rotated.")
	case "leave":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier channel leave <channel-id>")
		}
		if err := cl.ChannelLeave(args[1]); err != nil {
			return err
		}
		fmt.Println("left the channel.")
	default:
		return fmt.Errorf("unknown channel subcommand %q (create|invite|join|send|inbox|list|remove|leave)", args[0])
	}
	return nil
}

func shortAddr(a string) string {
	a = strings.TrimPrefix(a, "ed25519:")
	if len(a) > 12 {
		return a[:12] + "…"
	}
	return a
}
