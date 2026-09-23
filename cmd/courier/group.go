// Group messaging CLI (issue #32).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

func groupUsage() string {
	return `admin-managed encrypted groups (issue #32): Courier's
multi-party primitive. The creator becomes the admin, and only the
admin can add or remove members or transfer adminship. Membership
changes are signed control messages; when a member is removed,
sender keys rotate so the removed member cannot read later messages.

usage:
  courier group create --name <name> [addr...]
      create a group; you become the admin. Addresses given are added
      as initial members.
      example: courier group create --name ops ed25519:AAA ed25519:BBB

  courier group add <group-id> <addr>
      add a member (admin only).

  courier group remove <group-id> <addr>
      remove a member (admin only). Sender keys rotate, so the removed
      member cannot decrypt later messages. The admin cannot remove
      themselves — transfer adminship first.

  courier group transfer <group-id> <addr>
      transfer adminship to a current member (admin only). You lose
      control rights immediately.

  courier group send <group-id> <message|->
      send to the group, sealed under your current sender key. "-"
      reads the body from stdin.
      example: courier group send grp_abc123 "deploy is green"

  courier group inbox <group-id>
      read new group messages. Syncs your direct inbox first (group
      invitations and sender-key updates arrive as DMs), then applies
      membership controls and decrypts group messages.

  courier group list
      list your groups, with admin and member counts.

  courier group show <group-id>
      show a group's name, admin, and full roster.`
}

func cmdGroup(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", groupUsage())
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("group create", flag.ContinueOnError)
		name := fs.String("name", "", "group name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" {
			return fmt.Errorf("usage: courier group create --name <name> [addr...]")
		}
		g, err := cl.GroupCreate(*name, fs.Args())
		if err != nil {
			return err
		}
		fmt.Printf("group %s created (admin: you)\n", g.ID)
	case "add":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier group add <group-id> <addr>")
		}
		if err := cl.GroupAdd(args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("added %s to %s\n", args[2], args[1])
	case "remove":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier group remove <group-id> <addr>")
		}
		if err := cl.GroupRemove(args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("removed %s from %s (sender keys rotated)\n", args[2], args[1])
	case "transfer":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier group transfer <group-id> <addr>")
		}
		if err := cl.GroupTransferAdmin(args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("adminship of %s transferred to %s\n", args[1], args[2])
	case "send":
		if len(args) < 3 {
			return fmt.Errorf("usage: courier group send <group-id> <message|->")
		}
		var body string
		if args[2] == "-" {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
			body = string(raw)
		} else {
			body = strings.Join(args[2:], " ")
		}
		if strings.TrimSpace(body) == "" {
			return fmt.Errorf("message body is empty")
		}
		id, err := cl.GroupSend(args[1], body)
		if err != nil {
			return err
		}
		fmt.Printf("sent to %s (id %d)\n", args[1], id)
	case "inbox":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier group inbox <group-id>")
		}
		return cmdGroupInbox(cl, cfg, args[1])
	case "list":
		gs, err := cl.GroupList()
		if err != nil {
			return err
		}
		if len(gs) == 0 {
			fmt.Println("no groups.")
			return nil
		}
		for _, g := range gs {
			status := ""
			if g.Removed {
				status = " [removed]"
			}
			fmt.Printf("%s  %q  admin %.12s  %d members%s\n",
				g.ID, g.Name, g.Admin, len(g.Roster), status)
		}
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier group show <group-id>")
		}
		gs, err := cl.GroupList()
		if err != nil {
			return err
		}
		for _, g := range gs {
			if g.ID != args[1] {
				continue
			}
			fmt.Printf("group:  %s\nname:   %s\nadmin:  %s\n", g.ID, g.Name, g.Admin)
			fmt.Printf("members (%d):\n", len(g.Roster))
			for _, m := range g.Roster {
				mark := ""
				if m == cfg.Address {
					mark = " (you)"
				}
				if m == g.Admin {
					mark += " [admin]"
				}
				fmt.Printf("  %s%s\n", m, mark)
			}
			if g.Removed {
				fmt.Println("status: you were removed from this group")
			}
			return nil
		}
		return fmt.Errorf("unknown group %s", args[1])
	default:
		return fmt.Errorf("unknown group subcommand %q\n%s", args[0], groupUsage())
	}
	return nil
}

// cmdGroupInbox syncs direct messages first (group invitations and
// sender-key updates arrive as DMs), then reads the group's messages.
func cmdGroupInbox(cl *client.Client, cfg *client.Config, groupID string) error {
	if _, err := envelope.ParseGroupID(groupID); err != nil {
		return err
	}
	// Direct messages carry group protocol traffic (invites, key
	// distributions), so sync them first. Any chat messages that arrive
	// are shown, like `courier inbox` does.
	msgs, lastID, skipped, _, err := cl.Inbox(cfg.Cursor, 50)
	if err != nil {
		return fmt.Errorf("direct inbox sync: %w", err)
	}
	after := lastID
	_ = cfg.Update(func(fresh *client.Config) error {
		fresh.Cursor = after
		return nil
	})
	if len(msgs) > 0 {
		fmt.Println("--- direct messages ---")
		printMessages(msgs)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "(%d direct message(s) failed signature/decryption and were dropped)\n", skipped)
	}
	gmsgs, err := cl.GroupInbox(groupID)
	if err != nil {
		return err
	}
	if len(gmsgs) == 0 {
		fmt.Println("no new group messages.")
		return nil
	}
	printGroupMessages(gmsgs)
	return nil
}

func printGroupMessages(msgs []client.Message) {
	for _, m := range msgs {
		ts := time.Unix(m.ReceivedAt, 0).UTC().Format("2006-01-02 15:04:05Z")
		fmt.Printf("[#%d] from %s at %s\n%s\n\n", m.ID, m.From, ts, m.Body)
	}
}
