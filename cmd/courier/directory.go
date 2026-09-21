// Contact-discovery directory commands (issue #39).
package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
)

func cmdDirectory(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: courier directory <register|update|unregister|transfer|lookup|search|reverse|request|introductions|forward|accept|dismiss>")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	c := client.New(cfg)
	switch args[0] {
	case "register":
		return cmdDirectoryRegister(c, args[1:])
	case "update":
		return cmdDirectoryUpdate(c, args[1:])
	case "unregister":
		if err := c.DirectoryUnregister(); err != nil {
			return err
		}
		fmt.Println("handle unregistered")
		return nil
	case "transfer":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier directory transfer <handle> <new-address>")
		}
		if err := c.DirectoryTransfer(args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("transferred @%s to %s\n", args[1], args[2])
		return nil
	case "lookup":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier directory lookup <handle>")
		}
		p, err := c.DirectoryLookup(args[1])
		if err != nil {
			return err
		}
		printProfile(p)
		return nil
	case "search":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier directory search <prefix>")
		}
		results, err := c.DirectorySearch(args[1])
		if err != nil {
			return err
		}
		if len(results) == 0 {
			fmt.Println("no matches")
			return nil
		}
		for _, p := range results {
			fmt.Printf("@%s  %s\n", p.Handle, strings.Join(p.Capabilities, ","))
		}
		return nil
	case "reverse":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier directory reverse <address>")
		}
		results, err := c.DirectoryReverse(args[1])
		if err != nil {
			return err
		}
		if len(results) == 0 {
			fmt.Println("no listed handle for that address")
			return nil
		}
		for _, p := range results {
			fmt.Printf("@%s  (%s)\n", p.Handle, p.Visibility)
		}
		return nil
	case "request":
		return cmdDirectoryRequest(c, args[1:])
	case "introductions":
		return cmdDirectoryIntroductions(c)
	case "forward":
		return cmdDirectoryForward(c, args[1:])
	case "accept":
		return cmdDirectoryAccept(c, args[1:])
	case "dismiss":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier directory dismiss <id>")
		}
		if err := c.DismissIntroduction(args[1]); err != nil {
			return err
		}
		fmt.Println("dismissed")
		return nil
	default:
		return fmt.Errorf("unknown directory subcommand %q", args[0])
	}
}

func cmdDirectoryRegister(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("directory register", flag.ContinueOnError)
	visibility := fs.String("visibility", "private", "public, unlisted, or private")
	caps := fs.String("caps", "", "comma-separated capability tokens")
	policy := fs.String("policy", "open", "open or contacts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: courier directory register <handle> [--visibility public|unlisted|private] [--caps a,b] [--policy open|contacts]")
	}
	var capList []string
	if *caps != "" {
		capList = strings.Split(*caps, ",")
	}
	if err := c.DirectoryRegister(fs.Arg(0), *visibility, capList, *policy); err != nil {
		return directoryHint(err)
	}
	fmt.Printf("registered @%s (%s)\n", fs.Arg(0), *visibility)
	return nil
}

func cmdDirectoryUpdate(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("directory update", flag.ContinueOnError)
	visibility := fs.String("visibility", "", "public, unlisted, or private")
	caps := fs.String("caps", "", "comma-separated capability tokens (replaces)")
	clearCaps := fs.Bool("clear-caps", false, "remove all capability tokens")
	policy := fs.String("policy", "", "open or contacts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: courier directory update [--visibility ...] [--caps a,b] [--clear-caps] [--policy ...]")
	}
	var capList []string
	if *caps != "" {
		capList = strings.Split(*caps, ",")
	}
	if err := c.DirectoryUpdate(*visibility, capList, *policy, *clearCaps); err != nil {
		return directoryHint(err)
	}
	fmt.Println("handle updated")
	return nil
}

// directoryHint adds the key-announcement remediation when the relay
// rejects registration for a missing published key.
func directoryHint(err error) error {
	if strings.Contains(err.Error(), "key announcement") {
		return fmt.Errorf("%v\n\nthe directory requires a published key announcement first: run `courier publish-key`, then retry", err)
	}
	return err
}

func cmdDirectoryRequest(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("directory request", flag.ContinueOnError)
	note := fs.String("note", "", "note for the introducer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: courier directory request <contact> <handle> [--note text]")
	}
	if err := c.RequestIntroduction(fs.Arg(0), fs.Arg(1), *note); err != nil {
		return err
	}
	fmt.Printf("introduction request sent to %s for @%s\n", fs.Arg(0), fs.Arg(1))
	return nil
}

func cmdDirectoryIntroductions(c *client.Client) error {
	pending := c.PendingIntroductions()
	if len(pending) == 0 {
		fmt.Println("no pending introductions")
		return nil
	}
	for _, pi := range pending {
		ts := time.Unix(pi.Ts, 0).Format("2006-01-02 15:04")
		switch pi.Kind {
		case "request":
			fmt.Printf("%s  [request] %s asks you to introduce them to @%s  (%s)\n",
				pi.ID, c.ContactDisplayName(pi.From), pi.Handle, ts)
			if pi.Note != "" {
				fmt.Printf("    note: %s\n", pi.Note)
			}
			fmt.Printf("    forward with: courier directory forward %s [--note text]\n", pi.ID)
		case "introduction":
			who := pi.SubjectHandle
			if who == "" {
				who = pi.Subject
			} else {
				who = "@" + who
			}
			fmt.Printf("%s  [introduction] %s introduces %s  (%s)\n",
				pi.ID, c.ContactDisplayName(pi.From), who, ts)
			if pi.Note != "" {
				fmt.Printf("    note: %s\n", pi.Note)
			}
			fmt.Printf("    accept with: courier directory accept %s [--greet text]\n", pi.ID)
		}
	}
	return nil
}

func cmdDirectoryForward(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("directory forward", flag.ContinueOnError)
	note := fs.String("note", "", "note for the target")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: courier directory forward <request-id> [--note text]")
	}
	if err := c.AcceptIntroductionRequest(fs.Arg(0), *note); err != nil {
		return err
	}
	fmt.Println("introduction sent")
	return nil
}

func cmdDirectoryAccept(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("directory accept", flag.ContinueOnError)
	greet := fs.String("greet", "", "greeting message (default provided)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: courier directory accept <introduction-id> [--greet text]")
	}
	if err := c.AcceptIntroduction(fs.Arg(0), *greet); err != nil {
		return err
	}
	fmt.Println("introduction accepted: contact added, greeting sent")
	return nil
}

func printProfile(p *client.DirectoryProfile) {
	fmt.Printf("handle:        @%s\n", p.Handle)
	fmt.Printf("address:       %s\n", p.Address)
	fmt.Printf("visibility:    %s\n", p.Visibility)
	fmt.Printf("contact policy: %s\n", p.ContactPolicy)
	if len(p.Capabilities) > 0 {
		fmt.Printf("capabilities:  %s\n", strings.Join(p.Capabilities, ", "))
	}
	fmt.Printf("registered:    %s\n", time.Unix(p.RegisteredAt, 0).Format("2006-01-02 15:04"))
}
