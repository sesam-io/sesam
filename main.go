package main

import (
	"fmt"
	"flag"
	"os"
	"errors"
	"bufio"
	"strings"
	"log"
	"net/http"
	"bytes"
	"archive/zip"
	"path/filepath"
	"io"
	"os/exec"
	"io/ioutil"
)

var Version string
var verboseFlag bool
var nodeFlag string
var jwtFlag string
const buildDir = "build"

func myUsage() {
	fmt.Fprintf(os.Stderr,"usage: %s [options] <command>\n", os.Args[0])
	text := `
Commands:
  clean	    Clean the build folder
  upload    Replace node config with local config
  download  Replace local config with node config
  status    Compare local config with node config
  run	    Run configuration until it stabilizes (not implemented yet)
  update    Update expected output with current output (not implemented yet)
  verify    Compare current output with expected output (not implemented yet)
  test      Upload, run and verify solution (not implemented yet)

Options:
`
	fmt.Fprintf(os.Stderr, text)
	flag.PrintDefaults()
}

func main() {
	versionPtr := flag.Bool("version", false, "print version number")
	flag.BoolVar(&verboseFlag, "v", false, "be verbose")
	flag.StringVar(&nodeFlag,"node", "", "service url")
	flag.StringVar(&jwtFlag, "jwt", "", "authorization token")
	flag.Usage = myUsage
	flag.Parse()
	if *versionPtr {
		// https://stackoverflow.com/questions/11354518/golang-application-auto-build-versioning
		fmt.Printf("sesam version %s\n", Version)
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		// TODO add sub command Usage
		flag.Usage()
		return
	}
	var err error
	command := args[0]
	switch command {
	case "clean":
		err = clean()
	case "upload":
		err = upload()
	case "download":
		err = download()
	case "status":
		err = status()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		// TODO add sub command Usage
		flag.Usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %s\n", command, err)
		os.Exit(1)
	}
}

func download() error {
	conn, err := connect()
	if err != nil {
		return err
	}

	tmp, err := ioutil.TempFile("", "sesam")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = conn.getZipConfig(tmp)

	if err != nil {
		return fmt.Errorf("failed to get zip conn, aborting: %s", err)
	}

	err = rmFiles(".", func(path string) bool {
		return strings.HasSuffix(path, ".conf.json")
	})
	err = unzipTo(tmp.Name(), ".")
	if err != nil {
		return err
	}
	fmt.Printf("Local conn replaced by node conn.\n")
	return nil
}


func clean() error {
	_, err := connect()
	if err != nil {
		return err
	}
	// TODO wipe old config from node?

	dir := filepath.Join(buildDir)
	err = os.RemoveAll(dir)
	if err != nil {
		return err
	}
	return nil
}

func upload() error {
	conn, err := connect()
	if err != nil {
		return err
	}

	buf, err := zipConfig()

	if err != nil {
		return err
	}

	err = conn.putZipConfig(buf)
	if err != nil {
		return err
	}
	fmt.Printf("Node conn replaced with local conn.\n")
	return nil
}

type prepDiffFunc func(dst *os.File) error

func prepDiff(path string, prepFunc prepDiffFunc) error {
	tmp, err := ioutil.TempFile("", "sesam")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	err = prepFunc(tmp)
	if err != nil {
		return err
	}

	err = unzipTo(tmp.Name(), path)
	if err != nil {
		return err
	}
	return nil
}

func status() error {
	conn, err := connect()
	if err != nil {
		return err
	}

	dir := filepath.Join(buildDir, "status")
	err = os.RemoveAll(dir)
	if err != nil {
		return err
	}

	local := filepath.Join(dir, "local")

	err = prepDiff(local, func(dst *os.File) error {
		buf, err := zipConfig()
		if err != nil {
			return err
		}
		return ioutil.WriteFile(dst.Name(), buf.Bytes(), 0644)
	})
	if err != nil {
		return err
	}

	node := filepath.Join(dir, "node")

	err = prepDiff(node, func(dst *os.File) error {
		return conn.getZipConfig(dst)
	})
	if err != nil {
		return err
	}

	// TODO write recursive diff in Golang...
	cmd := exec.Command("diff", "-r", local, node)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		fmt.Println(err)
		fmt.Print(out.String())
		fmt.Fprint(os.Stderr, "Node conn is NOT in sync with local conn.\n")
		return nil
	}
	fmt.Printf("Node conn is up-to-date with local conn.\n")
	return nil
}

type pathMatchFunc func(path string) bool

func rmFiles(dir string, matcher pathMatchFunc) error {
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
		if verboseFlag {
			log.Printf("Removed %s\n", path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}


func zipDir(src string, matcher pathMatchFunc) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if !matcher(path) {
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
		if verboseFlag {
			log.Printf("Added %s (%d bytes written)\n", path, written)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func unzip(f *zip.File, dst string) error {
	if f.FileInfo().IsDir() {
		// ignore empty directories
		return nil
	}
	file, err := f.Open()
	defer file.Close()
	if err != nil {
		return err
	}

	path := filepath.Join(dst, f.Name)
	err = os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return err
	}
	d, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer d.Close()
	_, err = io.Copy(d, file)
	if err != nil {
		return err
	}
	return nil
}

func unzipTo(src string, dst string) error {
	reader, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	for _, f := range reader.File {
		unzip(f, dst)
	}
	return nil
}

func zipConfig() (*bytes.Buffer, error) {
	return zipDir(".", func(path string) bool {
		if path == "node-metadata.conf.json" {
			return true
		}
		if !strings.HasPrefix(path, "pipes/") && !strings.HasPrefix(path, "systems/") {
			return false
		}
		return strings.HasSuffix(path, ".conf.json")
	})
}

type connection struct {
	Jwt, Node string
}

func cleanJwt(token string) string {
	// strip away bearer in case user just copied the header value
	token = strings.Replace(token, "bearer ", "", 1)
	// drop quotes that user might have added
	return strings.Replace(token, "\"", "", -1)
}

func fixNodeUrl(url string) string {
	// drop quotes that user might have added
	url = strings.Replace(url, "\"", "", -1)
	// node is a url, use it as-is
	if strings.HasPrefix(url, "http") {
		return url
	} else {
		return fmt.Sprintf("https://%s/api", url)
	}
}

func loadSyncConfig() (*os.File, error) {
	config := ".syncconfig"
	file, err := os.Open(config)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to open %s", config))
	}
	defer file.Close()
	return file, nil
}

type parseResult struct {
	jwt, node string
}

func parseSyncConfig(r *parseResult, f *os.File) (error) {
	// parse property-style
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			setting := strings.Split(line, "=")
			if len(setting) != 2 {
				return fmt.Errorf("invalid conn line: %s", line)
			}
			switch strings.ToLower(setting[0]) {
			case "jwt":
				r.jwt = setting[1]
			case "node":
				r.node = setting[1]
			default:
				return fmt.Errorf("unknown conn key: %s", setting[0])
			}
		}
	}
	return nil
}

func coalesce(list []string) string {
	for _, v := range list {
		if v != "" {
			return v
		}
	}
	return ""
}

// loads conn from .syncconfig in current directory if not overridden by env variables
// TODO should walk up path to find file?
// TODO rename file to .sesam/config and use INI-style sections?
func connect() (*connection, error) {
	r := &parseResult{}
	f, err := loadSyncConfig()
	if err == nil {
		// file exists
		parseErr := parseSyncConfig(r, f)
		if parseErr != nil {
			// fail if parse errors
			return nil, parseErr
		}
	}
	jwt := coalesce([]string{jwtFlag, os.Getenv("JWT"), r.jwt})
	node := coalesce([]string{nodeFlag, os.Getenv("NODE"), r.node})

	if jwt == "" || node == "" {
		// still no valid config, lets tell the user that
		if err != nil {
			return nil, fmt.Errorf("jwt and node must be specifed either as parameter, os env or in config file")
		}
	}
	return &connection{Jwt: cleanJwt(jwt), Node: fixNodeUrl(node)}, nil
}

func (conn *connection) doRequest(r *http.Request) (*http.Response, error) {
	client := &http.Client{}
	r.Header.Add("Authorization", fmt.Sprintf("bearer %s", conn.Jwt))
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

func (conn *connection) putZipConfig(zip *bytes.Buffer) error {
	reader := bufio.NewReader(zip)

	r, err := http.NewRequest("PUT", fmt.Sprintf("%s/conn?force=true", conn.Node), reader)
	if err != nil {
		// shouldn't happen if conn is sane
		return fmt.Errorf("unable to create request: %v", err)
	}
	r.Header.Add("Content-Type", "application/zip")

	_, err = conn.doRequest(r)
	if err != nil {
		return err
	}
	return nil
}

func (conn *connection) getZipConfig(dst *os.File) error {
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/conn", conn.Node), nil)
	if err != nil {
		// shouldn't happen if conn is sane
		return fmt.Errorf("unable to create request: %v", err)
	}
	r.Header.Add("Accept", "application/zip")

	resp, err := conn.doRequest(r)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	io.Copy(dst, resp.Body)
	return nil
}
