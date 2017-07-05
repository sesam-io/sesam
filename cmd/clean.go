package main

import (
	"../sesam"
	"log"
	"os"
	"path/filepath"
)

func Clean() error {
	config, err := sesam.LoadConfig()
	if err != nil {
		return err
	}

	dir := filepath.Join(config.BuildDir)
	err = os.RemoveAll(dir)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	err := Clean()
	if err != nil {
		log.Fatalf("Failed to remove build directory: %s", err)
	}
}
