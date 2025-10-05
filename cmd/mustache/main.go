package main

import (
	"os"

	"github.com/herrBez/logstash-config/internal/app"
)

var Version = "(unknown)"

func main() {
	exitCode := app.Execute(Version, os.Stdout, os.Stderr)
	os.Exit(exitCode)
}
