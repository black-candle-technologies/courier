// Shared agent state CLI (issue #49).
package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
)

func stateUsage() string {
	return `usage:
  courier state note add <peer> --title <t> [--body <b>]   share a note
  courier state note done <peer> <note-id>                 mark note done
  courier state note reopen <peer> <note-id>               reopen a note
  courier state task add <peer> --title <t> [--body <b>] [--assignee <addr|contact>] [--escalate]
                                                          share a task
  courier state task assign <peer> <task-id> --assignee <addr|contact>
  courier state task done <peer> <task-id>                 (assignee only)
  courier state task reopen <peer> <task-id>               (assigner only)
  courier state list <peer> [--all]                       list notes + tasks (--all incl. done)
  courier state show <peer> <id>                          show one note or task
  courier state search <peer> <query>                     search notes + tasks locally
  courier state sync <peer>                               catch-up: fetch + apply missed events
  courier state compact <peer> [--days N]                 compact note events older than N days (default 90)

<peer> is an address or contact name. <id> accepts an unambiguous prefix.`
}

// splitStateFlags separates positional args from --flags, since Go's
// flag package stops parsing at the first positional (see splitSendArgs
// for the same fix on `courier send`). specs maps a flag name to whether
// it takes a value (false = boolean flag).
func splitStateFlags(args []string, specs map[string]bool) (positional []string, flags map[string]string, err error) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			name, inline := a[2:], ""
			if j := strings.IndexByte(name, '='); j >= 0 {
				name, inline = name[:j], name[j+1:]
			}
			takesValue, ok := specs[name]
			if !ok {
				return nil, nil, fmt.Errorf("unknown flag --%s", name)
			}
			if takesValue {
				if inline != "" {
					flags[name] = inline
				} else {
					if i+1 >= len(args) {
						return nil, nil, fmt.Errorf("--%s needs a value", name)
					}
					flags[name] = args[i+1]
					i++
				}
			} else {
				if inline != "" {
					return nil, nil, fmt.Errorf("--%s takes no value", name)
				}
				flags[name] = "true"
			}
			continue
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			return nil, nil, fmt.Errorf("unknown flag %s (use --flags)", a)
		}
		positional = append(positional, a)
	}
	return positional, flags, nil
}

func cmdState(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", stateUsage())
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	switch args[0] {
	case "note":
		return cmdStateNote(cl, args[1:])
	case "task":
		return cmdStateTask(cl, args[1:])
	case "list":
		pos, flags, err := splitStateFlags(args[1:], map[string]bool{"all": false})
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("usage: courier state list <peer> [--all]")
		}
		return cmdStateList(cl, pos[0], flags["all"] == "true")
	case "show":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier state show <peer> <id>")
		}
		return cmdStateShow(cl, args[1], args[2])
	case "search":
		if len(args) < 3 {
			return fmt.Errorf("usage: courier state search <peer> <query>")
		}
		return cmdStateSearch(cl, args[1], strings.Join(args[2:], " "))
	case "sync":
		if len(args) != 2 {
			return fmt.Errorf("usage: courier state sync <peer>")
		}
		n, err := cl.StateSync(args[1])
		if err != nil {
			return err
		}
		fmt.Printf("synced %d new event(s) with %s\n", n, args[1])
		return nil
	case "compact":
		pos, flags, err := splitStateFlags(args[1:], map[string]bool{"days": true})
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("usage: courier state compact <peer> [--days N]")
		}
		days := 90
		if v, ok := flags["days"]; ok {
			days, err = strconv.Atoi(v)
			if err != nil || days < 0 {
				return fmt.Errorf("--days must be a non-negative number")
			}
		}
		n, err := cl.StateCompact(pos[0], days)
		if err != nil {
			return err
		}
		fmt.Printf("compacted %d note event(s) with %s\n", n, pos[0])
		return nil
	default:
		return fmt.Errorf("%s", stateUsage())
	}
}

func cmdStateNote(cl *client.Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", stateUsage())
	}
	switch args[0] {
	case "add":
		pos, flags, err := splitStateFlags(args[1:], map[string]bool{"title": true, "body": true})
		if err != nil {
			return err
		}
		if len(pos) != 1 || flags["title"] == "" {
			return fmt.Errorf("usage: courier state note add <peer> --title <t> [--body <b>]")
		}
		id, envID, err := cl.StateAddNote(pos[0], flags["title"], flags["body"])
		if err != nil {
			return err
		}
		fmt.Printf("note %s shared (envelope %d)\n", id[:8], envID)
		return nil
	case "done", "reopen":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier state note %s <peer> <note-id>", args[0])
		}
		done := args[0] == "done"
		if _, err := cl.StateSetNoteDone(args[1], args[2], done); err != nil {
			return err
		}
		fmt.Printf("note %s marked %s\n", args[2], map[bool]string{true: "done", false: "reopened"}[done])
		return nil
	default:
		return fmt.Errorf("%s", stateUsage())
	}
}

func cmdStateTask(cl *client.Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", stateUsage())
	}
	switch args[0] {
	case "add":
		pos, flags, err := splitStateFlags(args[1:], map[string]bool{"title": true, "body": true, "assignee": true, "escalate": false})
		if err != nil {
			return err
		}
		if len(pos) != 1 || flags["title"] == "" {
			return fmt.Errorf("usage: courier state task add <peer> --title <t> [--body <b>] [--assignee <a>] [--escalate]")
		}
		id, envID, err := cl.StateAddTask(pos[0], flags["title"], flags["body"], flags["assignee"], flags["escalate"] == "true")
		if err != nil {
			return err
		}
		fmt.Printf("task %s shared (envelope %d)\n", id[:8], envID)
		return nil
	case "assign":
		pos, flags, err := splitStateFlags(args[1:], map[string]bool{"assignee": true})
		if err != nil {
			return err
		}
		if len(pos) != 2 || flags["assignee"] == "" {
			return fmt.Errorf("usage: courier state task assign <peer> <task-id> --assignee <a>")
		}
		if _, err := cl.StateAssignTask(pos[0], pos[1], flags["assignee"]); err != nil {
			return err
		}
		fmt.Printf("task %s reassigned\n", pos[1])
		return nil
	case "done":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier state task done <peer> <task-id>")
		}
		if _, err := cl.StateCompleteTask(args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("task %s done\n", args[2])
		return nil
	case "reopen":
		if len(args) != 3 {
			return fmt.Errorf("usage: courier state task reopen <peer> <task-id>")
		}
		if _, err := cl.StateReopenTask(args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("task %s reopened\n", args[2])
		return nil
	default:
		return fmt.Errorf("%s", stateUsage())
	}
}

func cmdStateList(cl *client.Client, peer string, all bool) error {
	notes, err := cl.StateListNotes(peer)
	if err != nil {
		return err
	}
	tasks, err := cl.StateListTasks(peer, "")
	if err != nil {
		return err
	}
	shown := 0
	fmt.Printf("notes with %s:\n", peer)
	for _, n := range notes {
		if n.Done && !all {
			continue
		}
		shown++
		fmt.Printf("  [%s] %s %s\n", n.ID[:8], doneMark(n.Done), n.Title)
	}
	if shown == 0 {
		fmt.Println("  (none)")
	}
	shown = 0
	fmt.Printf("tasks with %s:\n", peer)
	for _, t := range tasks {
		if t.State == client.StateTaskDone && !all {
			continue
		}
		shown++
		esc := ""
		if t.Escalate {
			esc = " [needs human]"
		}
		fmt.Printf("  [%s] %s %s (assignee %s)%s\n", t.ID[:8], taskMark(t.State), t.Title, shortAddr(t.Assignee), esc)
	}
	if shown == 0 {
		fmt.Println("  (none)")
	}
	return nil
}

func cmdStateShow(cl *client.Client, peer, prefix string) error {
	notes, err := cl.StateListNotes(peer)
	if err != nil {
		return err
	}
	tasks, err := cl.StateListTasks(peer, "")
	if err != nil {
		return err
	}
	var matchN *client.StateNote
	var matchT *client.StateTask
	matches := 0
	for _, n := range notes {
		if strings.HasPrefix(n.ID, prefix) {
			matchN, matches = n, matches+1
		}
	}
	for _, t := range tasks {
		if strings.HasPrefix(t.ID, prefix) {
			matchT, matches = t, matches+1
		}
	}
	switch {
	case matches == 0:
		return fmt.Errorf("unknown note/task id %q", prefix)
	case matches > 1:
		return fmt.Errorf("ambiguous id prefix %q", prefix)
	case matchN != nil:
		n := matchN
		fmt.Printf("note %s\n  title: %s\n  done: %v\n  author: %s\n  created: %s\n  updated: %s\n",
			n.ID, n.Title, n.Done, shortAddr(n.Author),
			time.Unix(n.CreatedAt, 0).Format(time.RFC3339),
			time.Unix(n.UpdatedAt, 0).Format(time.RFC3339))
		if n.Body != "" {
			fmt.Printf("  body: %s\n", n.Body)
		}
		return nil
	default:
		t := matchT
		fmt.Printf("task %s\n  title: %s\n  state: %s\n  assignee: %s\n  assigner: %s\n  escalate: %v\n  author: %s\n  created: %s\n  updated: %s\n",
			t.ID, t.Title, t.State, shortAddr(t.Assignee), shortAddr(t.Assigner),
			t.Escalate, shortAddr(t.Author),
			time.Unix(t.CreatedAt, 0).Format(time.RFC3339),
			time.Unix(t.UpdatedAt, 0).Format(time.RFC3339))
		if t.Body != "" {
			fmt.Printf("  body: %s\n", t.Body)
		}
		if t.DoneBy != "" {
			fmt.Printf("  done by: %s\n", shortAddr(t.DoneBy))
		}
		return nil
	}
}
func cmdStateSearch(cl *client.Client, peer, query string) error {
	notes, tasks, err := cl.StateSearch(peer, query)
	if err != nil {
		return err
	}
	for _, n := range notes {
		fmt.Printf("note [%s] %s %s\n", n.ID[:8], doneMark(n.Done), n.Title)
	}
	for _, t := range tasks {
		fmt.Printf("task [%s] %s %s\n", t.ID[:8], taskMark(t.State), t.Title)
	}
	if len(notes)+len(tasks) == 0 {
		fmt.Println("no matches.")
	}
	return nil
}

func doneMark(done bool) string {
	if done {
		return "☑"
	}
	return "☐"
}

func taskMark(state string) string {
	if state == client.StateTaskDone {
		return "✅"
	}
	return "📌"
}
