package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/black-candle-technologies/courier/internal/client"
)

// A command owns its resolved context; no package-global current host exists.
type command struct{ context client.Context }

func selectCommand(args []string) (command, []string, error) {
	legacy := client.LegacyContext()
	scope := command{context: legacy}
	host, identity := "", ""
	for len(args) > 0 && (args[0] == "--host" || args[0] == "--identity") {
		if len(args) < 2 || args[1] == "" {
			return scope, nil, fmt.Errorf("selector requires a value")
		}
		if args[0] == "--host" {
			if host != "" {
				return scope, nil, fmt.Errorf("duplicate host selector")
			}
			host = args[1]
		} else {
			if identity != "" {
				return scope, nil, fmt.Errorf("duplicate identity selector")
			}
			identity = args[1]
		}
		args = args[2:]
	}
	if host == "" && identity == "" {
		ctx, err := legacy.ActiveContext()
		scope.context = ctx
		return scope, args, err
	}
	if host == "" {
		return scope, nil, fmt.Errorf("--identity requires an explicit --host")
	}
	root, err := legacy.StateRoot()
	if err != nil {
		return scope, nil, err
	}
	f, err := os.Open(filepath.Join(root, "hosts.json"))
	if err != nil {
		return scope, nil, err
	}
	defer f.Close()
	var hosts client.Hosts
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&hosts); err != nil {
		return scope, nil, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return scope, nil, fmt.Errorf("hosts registry must contain exactly one JSON object")
	}
	ctx, err := hosts.Resolve(root, host, identity)
	if err != nil {
		return scope, nil, err
	}
	return command{context: ctx}, args, nil
}

func (scope command) cmdContext(args []string) error {
	if len(args) == 0 || args[0] != "migrate" {
		return fmt.Errorf("usage: courier --host HOST context migrate --confirm-legacy-writers-stopped")
	}
	fs := flag.NewFlagSet("context migrate", flag.ContinueOnError)
	stopped := fs.Bool("confirm-legacy-writers-stopped", false, "confirm all legacy daemons and writers have stopped")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected migration arguments")
	}
	return client.LegacyContext().MigrateLegacy(scope.context, client.MigrationOptions{ConfirmLegacyWritersStopped: *stopped})
}
