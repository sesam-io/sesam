package sesam

import (
	"../util"
	"bytes"
	"strings"
)

func ZipConfig() (*bytes.Buffer, error) {
	return util.ZipDir(".", func(path string) bool {
		if path == "node-metadata.conf.json" {
			return true
		}
		if !strings.HasPrefix(path, "pipes/") && !strings.HasPrefix(path, "systems/") {
			return false
		}
		return strings.HasSuffix(path, ".conf.json")
	})
}