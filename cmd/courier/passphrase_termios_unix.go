//go:build unix

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// readPassphraseTerminal prompts on stderr and reads a passphrase from
// the terminal with echo disabled, restoring the terminal state after.
func readPassphraseTerminal(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, termiosGet)
	if err != nil {
		return "", fmt.Errorf("terminal: %w", err)
	}
	noEcho := *old
	noEcho.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, termiosSet, &noEcho); err != nil {
		return "", fmt.Errorf("terminal: %w", err)
	}
	defer unix.IoctlSetTermios(fd, termiosSet, old) //nolint:errcheck
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
