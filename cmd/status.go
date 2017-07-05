package main

import (
	"../sesam"
	"../util"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

type PrepDiffFunc func(dst *os.File) error

func PrepDiff(path string, prepFunc PrepDiffFunc) error {
	tmp, err := ioutil.TempFile("", "sesam")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	err = prepFunc(tmp)
	if err != nil {
		return err
	}

	err = util.UnzipTo(tmp.Name(), path)
	if err != nil {
		return err
	}
	return nil
}

func Status() (bool, error) {
	config, err := sesam.LoadConfig()
	if err != nil {
		return false, err
	}

	dir := filepath.Join(config.BuildDir, "status")
	err = os.RemoveAll(dir)
	if err != nil {
		return false, err
	}

	local := filepath.Join(dir, "local")

	err = PrepDiff(local, func(dst *os.File) error {
		buf, err := sesam.ZipConfig()
		if err != nil {
			return err
		}
		return ioutil.WriteFile(dst.Name(), buf.Bytes(), 0644)
	})
	if err != nil {
		return false, err
	}

	node := filepath.Join(dir, "node")

	err = PrepDiff(node, func(dst *os.File) error {
		return sesam.GetZipConfig(dst, config)
	})
	if err != nil {
		return false, err
	}

	// TODO write recursive diff in Golang...
	cmd := exec.Command("diff", "-r", local, node)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		fmt.Println(err)
		fmt.Print(out.String())
		return false, nil
	}
	return true, nil
}

func main() {
	equal, err := Status()
	if err != nil {
		log.Fatalf("Failed to compare configuration: %s", err)
	}
	if !equal {
		log.Fatalf("Node config is NOT in sync with local config.")
	}
	log.Printf("Node config is up-to-date with local config.")
}
