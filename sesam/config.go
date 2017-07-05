package sesam

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Jwt, Node, BuildDir string
}

func CleanJwt(token string) string {
	// strip away bearer in case user just copied the header value
	token = strings.Replace(token, "bearer ", "", 1)
	// drop quotes that user might have added
	return strings.Replace(token, "\"", "", -1)
}

func FixNodeUrl(url string) string {
	// node is a url, use it as-is
	if strings.HasPrefix(url, "http") {
		return url
	} else {
		return fmt.Sprintf("https://%s/api", url)
	}
}

// loads config from .syncconfig in current directory if not overriden by env variables
// TODO should walk up path to find file?
// TODO rename file to .sesam/config and use INI-style sections?
func LoadConfig() (*Config, error) {
	jwt := os.Getenv("JWT")
	node := os.Getenv("NODE")
	if jwt == "" || node == "" {
		// load config file if missing env variables
		config := ".syncconfig"
		file, err := os.Open(config)
		if err != nil {
			return nil, errors.New("unable to open config file")
		}
		defer file.Close()

		// parse property-style
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "#") {
				setting := strings.Split(line, "=")
				if len(setting) != 2 {
					return nil, fmt.Errorf("invalid config line: %s", line)
				}
				switch strings.ToLower(setting[0]) {
				case "jwt":
					jwt = setting[1]
				case "node":
					node = setting[1]
				default:
					return nil, fmt.Errorf("unknown config key: %s", setting[0])
				}
			}
		}
	}

	return &Config{Jwt: CleanJwt(jwt), Node: FixNodeUrl(node), BuildDir: "./build"}, nil
}
