package util

import (
	"log"
	"os"
	"path/filepath"
)

type PathMatchFunc func(path string) bool

func RmFiles(dir string, matcher PathMatchFunc) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if !matcher(path) {
			return nil
		}
		err = os.Remove(path)
		if err != nil {
			return err
		}
		// TODO print only if verbose
		log.Printf("Removed %s\n", path)
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
