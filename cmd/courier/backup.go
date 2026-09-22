package main

// courier backup: encrypted identity backup and multi-device sync
// (issue #47). Backup and sync share one envelope format and KDF
// (internal/crypto); the subcommands differ only in intent:
//
//	create      write an encrypted backup file (seed + live keys)
//	restore     install a backup file as this machine's identity
//	export-sync write an encrypted sync envelope (live key material)
//	import-sync merge a sync envelope's keys into this identity

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/mattn/go-isatty"
)

func cmdBackup(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: courier backup <create|restore|export-sync|import-sync>")
	}
	switch args[0] {
	case "create":
		return cmdBackupCreate(args[1:])
	case "restore":
		return cmdBackupRestore(args[1:])
	case "export-sync":
		return cmdBackupExportSync(args[1:])
	case "import-sync":
		return cmdBackupImportSync(args[1:])
	default:
		return fmt.Errorf("unknown backup subcommand %q (create|restore|export-sync|import-sync)", args[0])
	}
}

// splitBackupArgs extracts the backup subcommand flags wherever they
// appear. Go's flag package stops parsing at the first positional
// argument, so `backup restore file --force` would otherwise break —
// the same gotcha v0.7.1 fixed for `send --attach` (splitSendArgs).
// Supports both `--flag value` and `--flag=value` forms.
func splitBackupArgs(args []string) (positionals []string, output, deviceName, passphraseEnv string, force bool) {
	strFlags := map[string]*string{
		"output":         &output,
		"device-name":    &deviceName,
		"passphrase-env": &passphraseEnv,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--force" {
			force = true
			continue
		}
		consumed := false
		for name, dst := range strFlags {
			if a == "--"+name && i+1 < len(args) {
				*dst = args[i+1]
				i++
				consumed = true
				break
			}
			if rest, ok := strings.CutPrefix(a, "--"+name+"="); ok {
				*dst = rest
				consumed = true
				break
			}
		}
		if !consumed {
			positionals = append(positionals, a)
		}
	}
	return positionals, output, deviceName, passphraseEnv, force
}

// backupPassphrase resolves the passphrase from --passphrase-env, from
// piped stdin, or from an interactive terminal prompt. When confirm is
// true (creating a new envelope) the prompt repeats and must match.
func backupPassphrase(passphraseEnv string, confirm bool) ([]byte, error) {
	if passphraseEnv != "" {
		p := os.Getenv(passphraseEnv)
		if p == "" {
			return nil, fmt.Errorf("env var %s is unset or empty", passphraseEnv)
		}
		return []byte(p), nil
	}
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading passphrase from stdin: %w", err)
		}
		p := strings.TrimRight(line, "\r\n")
		if p == "" {
			return nil, errors.New("empty passphrase on stdin")
		}
		return []byte(p), nil
	}
	p, err := readPassphraseTerminal("backup passphrase")
	if err != nil {
		return nil, err
	}
	if p == "" {
		return nil, errors.New("empty passphrase")
	}
	if confirm {
		again, err := readPassphraseTerminal("repeat backup passphrase")
		if err != nil {
			return nil, err
		}
		if p != again {
			return nil, errors.New("passphrases do not match")
		}
	}
	return []byte(p), nil
}

func backupOutputPath(flagVal, prefix string) string {
	if flagVal != "" {
		return flagVal
	}
	return fmt.Sprintf("%s-%s.json", prefix, time.Now().Format("20060102-150405"))
}

func writeBackupFile(path string, raw []byte) error {
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	return nil
}

func cmdBackupCreate(args []string) error {
	positionals, output, deviceName, passphraseEnv, _ := splitBackupArgs(args)
	if len(positionals) != 0 {
		return errors.New("usage: courier backup create [--output f] [--device-name n] [--passphrase-env VAR]")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	pass, err := backupPassphrase(passphraseEnv, true)
	if err != nil {
		return err
	}
	raw, err := cfg.CreateBackup(pass, crypto.BackupKindBackup, deviceName)
	if err != nil {
		return err
	}
	path := backupOutputPath(output, "courier-backup")
	if err := writeBackupFile(path, raw); err != nil {
		return err
	}
	fmt.Printf("backup written to %s\n", path)
	fmt.Printf("  identity: %s\n", cfg.Address)
	fmt.Printf("  encryption keys: %d\n", len(cfg.EncKeys))
	fmt.Println("Keep this file and your passphrase safe: together they own this identity.")
	return nil
}

func cmdBackupExportSync(args []string) error {
	positionals, output, deviceName, passphraseEnv, _ := splitBackupArgs(args)
	if len(positionals) != 0 {
		return errors.New("usage: courier backup export-sync [--output f] [--device-name n] [--passphrase-env VAR]")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	pass, err := backupPassphrase(passphraseEnv, true)
	if err != nil {
		return err
	}
	raw, err := cfg.CreateBackup(pass, crypto.BackupKindSync, deviceName)
	if err != nil {
		return err
	}
	path := backupOutputPath(output, "courier-sync")
	if err := writeBackupFile(path, raw); err != nil {
		return err
	}
	fmt.Printf("sync envelope written to %s\n", path)
	fmt.Printf("  identity: %s\n", cfg.Address)
	fmt.Printf("  encryption keys: %d\n", len(cfg.EncKeys))
	fmt.Println("Move this file to your other device and run: courier backup import-sync <file>")
	fmt.Println("Use the same passphrase on both devices.")
	return nil
}

func cmdBackupRestore(args []string) error {
	positionals, _, _, passphraseEnv, force := splitBackupArgs(args)
	if len(positionals) != 1 {
		return errors.New("usage: courier backup restore [--force] [--passphrase-env VAR] <backup-file>")
	}
	raw, err := os.ReadFile(positionals[0])
	if err != nil {
		return err
	}
	pass, err := backupPassphrase(passphraseEnv, false)
	if err != nil {
		return err
	}
	cfg, err := client.RestoreBackup(pass, raw, force)
	if err != nil {
		return err
	}
	fmt.Println("identity restored. Your address:")
	fmt.Println("  " + cfg.Address)
	fmt.Printf("  encryption keys: %d\n", len(cfg.EncKeys))
	fmt.Println("  forward-secrecy sessions were erased: this is a new device, so peers will re-handshake on the next message.")
	// Best effort: announce the current key so the relay directory is
	// correct for this device. A stale backup's announcement is safely
	// rejected as a rollback; `courier publish-key` republishes later.
	if err := client.New(cfg).PublishKey(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not publish encryption key: %v\n", err)
		fmt.Fprintf(os.Stderr, "run `courier publish-key` once the relay is reachable.\n")
	}
	fmt.Println("If another device holds this identity, run `courier backup import-sync` with a fresh envelope from it, then `courier rotate` for good hygiene.")
	return nil
}

func cmdBackupImportSync(args []string) error {
	positionals, _, _, passphraseEnv, _ := splitBackupArgs(args)
	if len(positionals) != 1 {
		return errors.New("usage: courier backup import-sync [--passphrase-env VAR] <sync-file>")
	}
	raw, err := os.ReadFile(positionals[0])
	if err != nil {
		return err
	}
	pass, err := backupPassphrase(passphraseEnv, false)
	if err != nil {
		return err
	}
	p, err := client.DecryptBackup(pass, raw)
	if err != nil {
		return err
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	added, err := cfg.MergeSyncKeys(p)
	if err != nil {
		return err
	}
	fmt.Printf("sync merged: %d new key(s), %d total\n", added, len(cfg.EncKeys))
	fmt.Printf("  current key epoch: %d\n", cfg.EncKeys[0].Epoch)
	return nil
}
