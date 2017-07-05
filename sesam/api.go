package sesam

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
)

func DoRequest(r *http.Request, config *Config) (*http.Response, error) {
	client := &http.Client{}
	r.Header.Add("Authorization", fmt.Sprintf("bearer %s", config.Jwt))
	resp, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("unable to do request: %v", err)
	}

	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("failed to talk to the node (got HTTP 403 Forbidden), maybe the JWT has expired?")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("expected http status code 200, got: %d", resp.StatusCode)
	}
	return resp, nil
}

func PutZipConfig(zip *bytes.Buffer, config *Config) error {
	reader := bufio.NewReader(zip)

	r, err := http.NewRequest("PUT", fmt.Sprintf("%s/config?force=true", config.Node), reader)
	if err != nil {
		// shouldn't happen if config is sane
		return fmt.Errorf("unable to create request: %v", err)
	}
	r.Header.Add("Content-Type", "application/zip")

	_, err = DoRequest(r, config)
	if err != nil {
		return err
	}
	return nil
}

func GetZipConfig(dest *os.File, config *Config) error {
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/config", config.Node), nil)
	if err != nil {
		// shouldn't happen if config is sane
		return fmt.Errorf("unable to create request: %v", err)
	}
	r.Header.Add("Accept", "application/zip")

	resp, err := DoRequest(r, config)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	io.Copy(dest, resp.Body)
	return nil
}
