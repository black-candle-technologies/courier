//go:build !unix

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// readPassphraseTerminal is the non-unix fallback: there is no portable
// no-echo API here, so the passphrase is read with echo on and the user
// is warned.
func readPassphraseTerminal(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "warning: cannot disable terminal echo on this platform; your passphrase will be visible.\n%s: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
