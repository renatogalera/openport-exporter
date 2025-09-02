package main

import (
    "log"
    "github.com/renatogalera/openport-exporter/cmd"
)

func main() {
    if err := cmd.Execute(); err != nil {
        log.Fatal(err)
    }
}
