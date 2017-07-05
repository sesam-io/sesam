package main

import (
	"../sesam"
	"../util"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func Download() error {
	config, err := sesam.LoadConfig()
	if err != nil {
		return err
	}

	tmp, err := ioutil.TempFile("", "sesam")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = sesam.GetZipConfig(tmp, config)

	if err != nil {
		return fmt.Errorf("failed to get zip config, aborting: %s", err)
	}

	err = util.RmFiles(".", func(path string) bool {
		return strings.HasSuffix(path, ".conf.json")
	})
	err = util.UnzipTo(tmp.Name(), ".")
	if err != nil {
		return err
	}
	return nil
}

func main() {
	err := Download()
	if err != nil {
		log.Fatalf("Failed to download config from the node: %s", err)
	}
	log.Printf("Local config replaced by node config\n")
}
