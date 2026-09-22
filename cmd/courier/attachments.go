package main

// courier attachments: re-download attachments from already-delivered
// messages (issue #136).
//
// `courier inbox` consumes a message whether or not --attachments-dir
// was passed, and the relay keeps the attachment bytes for 30 days —
// but until this command there was no way to reach them again: the
// replay-suppression hash was already recorded and the blob id lived
// only inside the consumed envelope.
//
//	fetch   re-fetch one message by id (bypassing replay suppression
//	        for that envelope only) and download its verified
//	        attachments into a directory

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/black-candle-technologies/courier/internal/client"
)

func cmdAttachments(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: courier attachments <fetch>")
	}
	switch args[0] {
	case "fetch":
		return cmdAttachmentsFetch(args[1:])
	default:
		return fmt.Errorf("unknown attachments subcommand %q (fetch)", args[0])
	}
}

func cmdAttachmentsFetch(args []string) error {
	fs := flag.NewFlagSet("attachments fetch", flag.ContinueOnError)
	msgID := fs.Int64("message", 0, "relay id of the already-delivered message to re-fetch")
	attachDir := fs.String("attachments-dir", "", "download and verify attachments into this directory (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *msgID <= 0 {
		return errors.New("--message <id> is required")
	}
	if *attachDir == "" {
		return errors.New("--attachments-dir <dir> is required")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	// Strictly read-only: FetchMessage bypasses replay suppression for
	// this envelope only — it marks nothing seen, moves no cursor, and
	// sends no receipts.
	msg, err := cl.FetchMessage(*msgID)
	if err != nil {
		return err
	}
	if len(msg.Attachments) == 0 {
		fmt.Printf("message #%d has no attachments.\n", msg.ID)
		return nil
	}
	// Same download-verify-save loop as `courier inbox
	// --attachments-dir`: every chunk is re-authenticated and the
	// reassembled SHA256 is checked (DownloadAttachment); saves never
	// overwrite (saveAttachment). Unlike the inbox poller, a partial
	// failure is fatal so scripts can tell they did not get everything.
	failed := false
	for _, a := range msg.Attachments {
		if a.KeyError != nil {
			fmt.Fprintf(os.Stderr, "[#%d] attachment %q: cannot decrypt: %v\n", msg.ID, a.Manifest.Filename, a.KeyError)
			failed = true
			continue
		}
		data, err := cl.DownloadAttachment(a)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[#%d] attachment %q: download failed: %v\n", msg.ID, a.Manifest.Filename, err)
			failed = true
			continue
		}
		path, err := saveAttachment(*attachDir, a.Manifest.Filename, data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[#%d] attachment %q: save failed: %v\n", msg.ID, a.Manifest.Filename, err)
			failed = true
			continue
		}
		fmt.Printf("[#%d] attachment saved: %s\n", msg.ID, path)
	}
	if failed {
		return fmt.Errorf("some attachments of message #%d could not be downloaded", msg.ID)
	}
	return nil
}
