package main

import (
	"testing"
	"path/filepath"
	"fmt"
)

func TestLoadSyncConfig(t *testing.T) {
	parent, _ := filepath.Split("/home/travis/build/datanav/jernbaneverket-sesam-config/sesam-home/sesam-node-railml-remodelling")
	assertEquals("/home/travis/build/datanav/jernbaneverket-sesam-config/sesam-home/", parent, t)
	parent, _ = filepath.Split("/home/travis/build/datanav/jernbaneverket-sesam-config/sesam-home")
	assertEquals("/home/travis/build/datanav/jernbaneverket-sesam-config/", parent, t)

	joined := filepath.Join("/foo/", "bar.json")
	assertEquals("/foo/bar.json", joined, t)
}

func assertEquals(expected string, actual string, t *testing.T) {
	if expected != actual {
		fmt.Printf("Expected %s, but got %s\n", expected, actual)
		t.Fail();
	}
}