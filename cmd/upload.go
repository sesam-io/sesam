package main

import (
	"../sesam"
	"log"
)

func Upload() error {
	config, err := sesam.LoadConfig()
	if err != nil {
		return err
	}

	buf, err := sesam.ZipConfig()

	if err != nil {
		return err
	}

	err = sesam.PutZipConfig(buf, config)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	err := Upload()
	if err != nil {
		log.Fatalf("Failed to upload config to the node: %s", err)
	}
	log.Printf("Node config replaced with local config\n")
}
