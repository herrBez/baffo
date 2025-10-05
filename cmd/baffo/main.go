package main

import (
	"os"

	"github.com/herrBez/baffo/internal/app"
)

var Version = "(unknown)"

func main() {
	exitCode := app.Execute(Version, os.Stdout, os.Stderr)
	os.Exit(exitCode)
}
