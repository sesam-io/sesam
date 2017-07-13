package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

func myUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <command>\n", os.Args[0])
	text := `
Commands:
  init	    Store a long lived JWT in current directory (not implemented yet)
  clean	    Clean the build folder
  upload    Replace node config with local config
  download  Replace local config with node config
  status    Compare node config with local config (requires external diff command)
  run	    Run configuration until it stabilizes (not implemented yet)
  update    Store current output as expected output
  verify    Compare output against expected output
  test      Upload, run and verify output

Options:
`
	fmt.Fprintf(os.Stderr, text)
	flag.PrintDefaults()
}

// injected during build process
var Version string

var verboseFlag bool
var nodeFlag string
var jwtFlag string
var singlePipeFlag string
var profileFlag string
var runsFlag int

const buildDir = "build"

func main() {
	versionPtr := flag.Bool("version", false, "print version number")
	flag.BoolVar(&verboseFlag, "v", false, "be verbose")
	flag.StringVar(&nodeFlag, "node", "", "service url")
	flag.StringVar(&jwtFlag, "jwt", "", "authorization token")
	flag.StringVar(&singlePipeFlag, "single", "", "update or verify just a single pipe")
	flag.StringVar(&profileFlag, "profile", "test", "env profile to use <profile>-env.json")
	flag.IntVar(&runsFlag, "runs", 1, "number of test runs to check for stability")
	flag.Usage = myUsage
	flag.Parse()
	if *versionPtr {
		// https://stackoverflow.com/questions/11354518/golang-application-auto-build-versioning
		fmt.Printf("sesam version %s\n", Version)
		return
	}

	args := flag.Args()
	if len(args) == 0 {
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
	case "update":
		err = update()
	case "verify":
		err = verify()
	case "test":
		err = test()
	case "run":
		err = run()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		flag.Usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %s\n", command, err)
		os.Exit(1)
	}
}

func run() error {
	// TODO
	// upload runner microservice
	// start microservice using proxy api
	// poll status api and display progress until finished or failed
	return fmt.Errorf("run not implemented yet")
}

func test() error {
	err := upload()
	if err != nil {
		return err
	}
	for i := 1; i <= runsFlag; i++ {
		err = run()
		if err != nil {
			return err
		}
		err = verify()
		if err != nil {
			return err
		}
		if verboseFlag {
			fmt.Printf("Finished test %d/%d..", i, runsFlag)
		}
	}
	return nil
}

type pipeHandler func(conn *connection, pipe *Pipe) error

func processOutputPipes(handler pipeHandler) error {
	conn, err := connect()
	if err != nil {
		return err
	}
	var pipes []Pipe
	err = conn.getPipes(&pipes)
	if err != nil {
		return fmt.Errorf("failed to get list of pipes: %s", err)
	}
	for _, pipe := range pipes {
		if pipe.getPipeType() == OutputPipe {
			err = handler(conn, &pipe)
			if err != nil {
				return fmt.Errorf("failed to test %s: %s", pipe.Id, err)
			}
		}
	}
	return nil
}

func getSpecs(update bool) ([]*testSpec, error) {
	files, err := ioutil.ReadDir("./expected")
	if err != nil {
		return nil, fmt.Errorf("failed to scan expected dir, does it exist?: %s", err)
	}
	pipes := make(map[string]bool)
	err = processOutputPipes(func(conn *connection, pipe *Pipe) error {
		pipes[pipe.Id] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	specs := []*testSpec{}
	testedPipes := make(map[string]int)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".test.json") {
			spec, err := loadSpec(f.Name())
			if err != nil {
				return nil, err
			}
			if !pipes[spec.Pipe] {
				return nil, fmt.Errorf("test references non-existing pipe %s, remove %s", spec.Pipe, f.Name())
			}
			testedPipes[spec.Pipe]++
			specs = append(specs, spec)
		}
	}
	for pipe, _ := range pipes {
		if testedPipes[pipe] < 1 {
			if !update {
				return nil, fmt.Errorf("no tests references pipe %s", pipe)
			}
			spec, err := createMissingSpec(pipe)
			if err != nil {
				return nil, err
			}
			specs = append(specs, spec)
		}
	}
	return specs, nil
}

func createMissingSpec(pipe string) (*testSpec, error) {
	if verboseFlag {
		log.Printf("Creating missing placeholder test spec for pipe: %s", pipe)
	}
	specName := fmt.Sprintf("./expected/%s.test.json", pipe)
	err := ioutil.WriteFile(specName, []byte("{\n}"), 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create missing spec file: %s", err)
	}
	spec, err := loadSpec(fmt.Sprintf("%s.test.json", pipe))
	if err != nil {
		return nil, err
	}
	return spec, nil
}

func handleSingle(conn *connection, spec *testSpec, update bool) error {
	// TODO store actual output if debugFlag is enabled and tests fails
	file := fmt.Sprintf("expected/%s", spec.File)
	if spec.Ignore {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			if update {
				err := os.Remove(file)
				if err != nil {
					return fmt.Errorf("failed to delete contents for ignored test: %s", err)
				}
			} else {
				return fmt.Errorf("%s is ignored, but %s still exists", spec.Pipe, spec.File)
			}
		}
		if verboseFlag {
			log.Printf("Ignoring %s", spec.Pipe)
		}
		return nil
	}
	switch spec.Endpoint {
	case "json":
		var entities []entity
		err := conn.getEntities(spec.Pipe, &entities)
		if err != nil {
			return fmt.Errorf("entities failed for %s: %s", spec.Pipe, err)
		}
		entities = normalizeList(spec, entities)
		sort.Sort(byId(entities))

		if update {
			bytes, _ := json.MarshalIndent(entities, "", "  ")
			err = ioutil.WriteFile(file, bytes, 0644)
			if err != nil {
				return fmt.Errorf("failed to updated expected file %s: %s", file, err)
			}
			return nil
		} else {
			expectedEntities := []entity{}
			raw, err := ioutil.ReadFile(file)
			if err != nil {
				return err
			}
			err = json.Unmarshal(raw, &expectedEntities)
			if err != nil {
				return fmt.Errorf("failed to parse expected entities %s", err)
			}
			if len(entities) != len(expectedEntities) {
				// TODO report with channels
				return fmt.Errorf("length mismatch: expected %d got %d", len(expectedEntities), len(entities))
			}
			for idx, entity := range entities {
				// just do a index lookup, in case ordering changes this might be hard to debug
				if !reflect.DeepEqual(entity, expectedEntities[idx]) {
					return fmt.Errorf("entity mismatch expected: %v got %v", expectedEntities[idx], entity)
				}
			}
			return nil
		}
	case "xml":
		bytes, err := conn.getXml(spec.Pipe, spec.Parameters)
		if err != nil {
			return fmt.Errorf("xml failed for %s: %s", spec.Pipe, err)
		}
		var entities interface{}
		err = xml.Unmarshal(bytes, &entities)
		if err != nil {
			return fmt.Errorf("failed to parse xml: %s", err)
		}

		// normalize if needed here

		if update {
			bytes, _ := xml.MarshalIndent(entities, "", "  ")
			err = ioutil.WriteFile(file, bytes, 0644)
			if err != nil {
				return fmt.Errorf("failed to updated expected file %s: %s", file, err)
			}
			return nil
		} else {
			var expectedEntities interface{}
			raw, err := ioutil.ReadFile(file)
			if err != nil {
				return err
			}
			err = xml.Unmarshal(raw, &expectedEntities)
			if err != nil {
				return fmt.Errorf("failed to parse expected xml %s", err)
			}
			if !reflect.DeepEqual(entities, expectedEntities) {
				// TODO report with channels
				return fmt.Errorf("xml content mismatch: expected %d got %d", expectedEntities, entities)
			}
			return nil
		}
	default:
		return fmt.Errorf("support for format %s not implemented yet", spec.Endpoint)
	}
}

func handle(update bool) ([]error, error) {
	conn, err := connect()
	if err != nil {
		return nil, err
	}
	if singlePipeFlag != "" {
		var spec *testSpec
		testFile := fmt.Sprintf("%s.test.json", singlePipeFlag)
		if _, err := os.Stat(fmt.Sprintf("expected/%s", testFile)); os.IsNotExist(err) {
			if !update {
				return nil, fmt.Errorf("no test spec: %s", testFile)
			}
			spec, err = createMissingSpec(singlePipeFlag)

			if err != nil {
				return nil, err
			}
		}
		spec, err = loadSpec(testFile)
		if err != nil {
			return nil, err
		}
		err = handleSingle(conn, spec, update)
		if err != nil {
			return []error{fmt.Errorf("%s: %s", singlePipeFlag, err)}, nil
		}
		return []error{}, nil
	}
	specs, err := getSpecs(true)
	if err != nil {
		return nil, err
	}
	errors := []error{}
	for _, spec := range specs {
		err := handleSingle(conn, spec, update)
		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %s", spec.Id, err))
		}
	}
	return errors, nil
}

func update() error {
	_, err := handle(true)
	return err
}

func verify() (error) {
	errors, err := handle(false)
	if err != nil {
		return err
	}
	if len(errors) > 0 {
		for _, err := range errors {
			fmt.Printf("test failed: %s\n", err)
		}
		return fmt.Errorf("%d tests failed", len(errors))
	}
	return nil
}

type entity map[string]interface{}

type byId []entity

func (a byId) Len() int           { return len(a) }
func (a byId) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byId) Less(i, j int) bool { return a[i]["_id"].(string) < a[j]["_id"].(string) }

type testSpec struct {
	Id                string   `json:"_id"`
	Ignore            bool     `json:"ignore"`
	Blacklist         []string `json:"blacklist"`
	File              string   `json:"file"`
	CompiledBlacklist []*regexp.Regexp
	Pipe              string            `json:"pipe"`
	Endpoint            string            `json:"endpoint"`
	Parameters        map[string]string `json:"parameters"`
}

func loadSpec(f string) (*testSpec, error) {
	// defaults
	name := strings.TrimSuffix(f, ".test.json")
	spec := testSpec{
		Id:     name,
		File:   fmt.Sprintf("%s.json", name),
		Endpoint: "json",
		Pipe:   name,
	}
	raw, err := ioutil.ReadFile(fmt.Sprintf("./expected/%s", f))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(raw, &spec)
	if err != nil {
		return nil, fmt.Errorf("failed to parse test spec: %s", err)
	}
	err = spec.compileBlacklist()
	if err != nil {
		return nil, err
	}
	return &spec, nil
}

func (spec testSpec) isBlacklisted(path []string) bool {
	expr := strings.Join(path, ".")
	for _, s := range spec.CompiledBlacklist {
		if s.MatchString(expr) {
			return true
		}
	}
	return false
}

// foo.bar -> foo\.bar
// foo[].bar -> foo.*.bar
func fixSyntax(i string) string {
	// the jq implementation used foo[].bar syntax when foo was a dict of objects (typically keys to new objects)
	i = strings.Replace(i, "[].", ".*.", -1)
	// create a regex, foo.*.bar -> ^foo\..*\.bar (the alternative would be that the end user typed regex directly)
	i = strings.Replace(i, ".", "\\.", -1)
	i = strings.Replace(i, "*", ".*", -1)
	return "^" + i
}

func (spec *testSpec) compileBlacklist() error {
	var rxs []*regexp.Regexp
	for _, s := range spec.Blacklist {
		c, err := regexp.Compile(fixSyntax(s))
		if err != nil {
			return err
		}
		rxs = append(rxs, c)
	}
	spec.CompiledBlacklist = rxs
	return nil
}

func normalizeList(spec *testSpec, entities []entity) []entity {
	var result []entity
	for _, entity := range entities {
		ctx := &normalizeContext{root: entity, spec: spec}
		result = append(result, ctx.normalize(entity, []string{}))
	}
	return result
}

type normalizeContext struct {
	root entity
	spec *testSpec
}

func (ctx normalizeContext) normalize(entity map[string]interface{}, parentPath []string) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range entity {
		path := append(parentPath, key)
		if key == "_id" || (key == "_deleted" && value == true) {
			result[key] = value
		} else if strings.HasPrefix(key, "_") {
			// ignore the other internal attributes
		} else {
			if !ctx.spec.isBlacklisted(path) {
				result[key] = ctx.normalizeValue(value, path)
			} else {
				if verboseFlag {
					log.Printf("_id %s: ignoring blacklisted path: %v ", ctx.root["_id"], path)
				}
			}
		}
	}
	return result
}

func (ctx normalizeContext) normalizeValue(v interface{}, path []string) interface{} {
	if v == nil {
		return v
	}
	rt := reflect.TypeOf(v)
	switch rt.Kind() {
	case reflect.Slice:
		fallthrough
	case reflect.Array:
		var fixed []interface{}
		for _, e := range v.([]interface{}) {
			fixed = append(fixed, ctx.normalizeValue(e, path))
		}
		return fixed
	case reflect.Map:
		return ctx.normalize(v.(map[string]interface{}), path)
	default:
		return v
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
		return fmt.Errorf("failed to get zip config, aborting: %s", err)
	}

	err = rmFiles(".", func(path string) bool {
		return strings.HasSuffix(path, ".conf.json")
	})
	err = unzipTo(tmp.Name(), ".")
	if err != nil {
		return err
	}
	fmt.Printf("Local config replaced by node config.\n")
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

	profileFile := fmt.Sprintf("%s-env.json", profileFlag)
	byte, err := ioutil.ReadFile(profileFile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s:", profileFile)
	}
	var env interface{}
	err = json.Unmarshal(byte, &env)
	if err != nil {
		return fmt.Errorf("failed to parse profile: %s", err)
	}
	err = conn.putEnv(env)
	if err != nil {
		return fmt.Errorf("failed to replace env: %s", err)
	}

	buf, err := zipConfig()

	if err != nil {
		return err
	}

	err = conn.putZipConfig(buf)
	if err != nil {
		return err
	}
	fmt.Printf("Node config replaced with local config.\n")
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
		fmt.Fprint(os.Stderr, "Node config is NOT in sync with local config.\n")
		return nil
	}
	fmt.Printf("Node config is up-to-date with local config.\n")
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
	return file, nil
}

type parseResult struct {
	jwt, node string
}

func parseSyncConfig(r *parseResult, f *os.File) error {
	// parse property-style
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			setting := strings.Split(line, "=")
			if len(setting) != 2 {
				return fmt.Errorf("invalid config line: %s", line)
			}
			switch strings.ToLower(setting[0]) {
			case "jwt":
				r.jwt = setting[1]
			case "node":
				r.node = setting[1]
			default:
				return fmt.Errorf("unknown config key: %s", setting[0])
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

// loads connection from .syncconfig in current directory if not overridden by env variables
// TODO should walk up path to find file?
// TODO rename file to .sesam/config and use INI-style sections?
func connect() (*connection, error) {
	r := &parseResult{}
	f, err := loadSyncConfig()
	defer f.Close()
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
	if verboseFlag {
		log.Printf("%v: %v\n", r.Method, r.URL)
	}
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

type Pipetype int

const (
	InputPipe Pipetype = iota
	InternalPipe
	OutputPipe
)

func (p Pipe) getPipeType() Pipetype {
	if p.Config.Effective.Source.Type == "embedded" {
		return InputPipe
	}
	if p.Config.Effective.Sink.Type == "dataset" {
		return InternalPipe
	}
	return OutputPipe
}

type PipeSource struct {
	Type string `json:"type"`
}

type PipeSink struct {
	Type string `json:"type"`
}

type PipeConfig struct {
	Source PipeSource `json:"source"`
	Sink   PipeSink   `json:"sink"`
}

type PipeConfigBlock struct {
	Effective PipeConfig `json:"effective"`
}

type Pipe struct {
	Id     string          `json:"_id"`
	Config PipeConfigBlock `json:"config"`
}

func (conn *connection) getPipes(target *[]Pipe) error {
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/pipes", conn.Node), nil)
	if err != nil {
		// shouldn't happen if connection is sane
		return fmt.Errorf("unable to create request: %v", err)
	}

	resp, err := conn.doRequest(r)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}

func (conn *connection) putZipConfig(zip *bytes.Buffer) error {
	reader := bufio.NewReader(zip)

	r, err := http.NewRequest("PUT", fmt.Sprintf("%s/config?force=true", conn.Node), reader)
	if err != nil {
		// shouldn't happen if connection is sane
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
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/config", conn.Node), nil)
	if err != nil {
		// shouldn't happen if connection is sane
		return fmt.Errorf("unable to create request: %v", err)
	}
	r.Header.Add("Accept", "application/zip")

	resp, err := conn.doRequest(r)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	_, err = io.Copy(dst, resp.Body)
	return err
}

func (conn *connection) getEntities(pipe string, target *[]entity) error {
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/pipes/%s/entities", conn.Node, pipe), nil)
	if err != nil {
		// shouldn't happen if connection is sane
		return fmt.Errorf("unable to create request: %v", err)
	}

	resp, err := conn.doRequest(r)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}

func (conn *connection) getXml(pipe string, parameters map[string]string,) ([]byte, error) {
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/publishers/%s/xml", conn.Node, pipe), nil)
	if err != nil {
		// shouldn't happen if connection is sane
		return nil, fmt.Errorf("unable to create request: %v", err)
	}

	resp, err := conn.doRequest(r)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func (conn *connection) putEnv(env interface{}) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	r, err := http.NewRequest("PUT", fmt.Sprintf("%s/env", conn.Node), bytes.NewBuffer(b))
	if err != nil {
		// shouldn't happen if connection is sane
		return fmt.Errorf("unable to create request: %v", err)
	}
	r.Header.Add("Content-Type", "application/json")

	_, err = conn.doRequest(r)
	if err != nil {
		return err
	}
	return nil
}
