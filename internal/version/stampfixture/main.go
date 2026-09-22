// Fixture for internal/version's stamp test: prints the four component
// versions, one per line. The test builds this program with -ldflags -X
// to prove the documented symbol paths actually take effect.
package main

import (
	"fmt"

	"github.com/black-candle-technologies/courier/internal/version"
)

func main() {
	fmt.Println(version.Client)
	fmt.Println(version.Relay)
	fmt.Println(version.Dashboard)
	fmt.Println(version.Bridge)
}
