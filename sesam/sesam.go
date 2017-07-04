package sesam

import (
	"fmt"
	"log"
	"bytes"
	"archive/zip"
	"path/filepath"
	"os"
	"io"
	"net/http"
	"bufio"
	"strings"
)

type Config struct {
	Jwt, Node string
}

// loads config from .syncconfig in current directory if not overriden by env variables
// TODO should walk up path to find file?
// TODO rename file to .sesam/config and use INI-style sections?
func LoadConfig() (Config) {
	jwt := os.Getenv("JWT")
	node := os.Getenv("NODE")
	if jwt != "" && node != "" {
		// drop file loading if all config is defined as env variables
		return Config{Jwt:jwt, Node: node}
	}
	config := ".syncconfig"
	file, err := os.Open(config)
	if err != nil {
		log.Fatalf("Unable to read config: %s\n", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			setting := strings.Split(line, "=")
			if len(setting) != 2 {
				log.Fatalf("Invalid config line: %s in %s\n", line, config)
			}
			switch strings.ToLower(setting[0]) {
			case "jwt":
				// strip away bearer in case user just copied the header value
				jwt = strings.Replace(setting[1], "bearer ", "", 1)
				// drop quotes that user might have added
				jwt = strings.Replace(jwt, "\"", "", -1)
			case "node":
				// node is a url, use it as-is
				if strings.HasPrefix(setting[1], "http") {
					node = setting[1]
				} else {
					node = fmt.Sprintf("https://%s/api", setting[1])
				}
			default:
				log.Fatalf("Unknown config property: %s\n", setting[0])
			}
		}
	}

	return Config{Jwt:jwt, Node: node}
}

func Upload() {
	config := LoadConfig()

	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".conf.json") {
			return nil
		}
		f, err := w.Create(path)
		if err != nil {
			return err
		}
		s, err := os.Open(path)
		if err != nil {
			return err
		}
		written, err := io.Copy(f, s)
		if err != nil {
			return err
		}
		log.Printf("Added %s (%d bytes written)\n", path, written)
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	err = w.Close()
	if err != nil {
		log.Fatal(err)
	}

	reader := bufio.NewReader(buf)

	client := http.Client{}
	r, err := http.NewRequest("PUT", fmt.Sprintf("%s/config?force=true", config.Node), reader)
	if err != nil {
		log.Fatal(err)
	}

	r.Header.Add("Authorization", fmt.Sprintf("bearer %s", config.Jwt))
	r.Header.Add("Content-Type", "application/zip")

	resp, err := client.Do(r)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		log.Fatal("Failed to upload config to the node. Maybe the JWT has expired?")
	}
	log.Printf("Node config replaced with local config\n")
}
