package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
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
	"time"
	"net/url"
	"github.com/beevik/etree"
	"github.com/satori/go.uuid"
	"crypto/tls"
)

func myUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <command>\n", os.Args[0])
	text := `
Commands:
  init	    Store a long lived JWT in current directory (not implemented yet)
  clean	    Clean the build folder
  wipe      Deletes all the pipes, systems, user datasets and environment variables in the node
  upload    Replace node config with local config
  download  Replace local config with node config
  status    Compare node config with local config (requires external diff command)
  run	    Run configuration until it stabilizes
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
var extraVerboseFlag bool
var skipTLSVerifyFlag bool
var nodeFlag string
var jwtFlag string
var singlePipeFlag string
var profileFlag string
var runsFlag int
var customSchedulerFlag bool
var schedulerIdFlag string
var dumpFlag bool
var printSchedulerLogFlag bool
var schedulerPollFreqFlag int
const schedulerImage = "sesamcommunity/scheduler:latest"
const schedulerPort = 5000

const buildDir = "build"

func main() {
	versionPtr := flag.Bool("version", false, "print version number")
	flag.BoolVar(&verboseFlag, "v", false, "be verbose")
	flag.BoolVar(&extraVerboseFlag, "vv", false, "be extra verbose")
	flag.BoolVar(&skipTLSVerifyFlag, "skip-tls-verification", false, "skip verifying the TLS certificate")
	flag.BoolVar(&dumpFlag, "dump", false, "dump zip content to disk")
	flag.BoolVar(&printSchedulerLogFlag, "print-scheduler-log", false, "print scheduler log during run")
	flag.BoolVar(&customSchedulerFlag, "custom-scheduler", false,"by default a scheduler system will be added, enable this flag if you have configured a custom scheduler as part of the config")
	flag.StringVar(&nodeFlag, "node", "", "service url")
	flag.StringVar(&jwtFlag, "jwt", "", "authorization token")
	flag.StringVar(&singlePipeFlag, "single", "", "update or verify just a single pipe")
	flag.StringVar(&profileFlag, "profile", "test", "env profile to use <profile>-env.json")
	flag.StringVar(&schedulerIdFlag, "scheduler-id", "scheduler", "system id for the scheduler system")
	flag.IntVar(&runsFlag, "runs", 1, "number of test cycles to check for stability")
	flag.IntVar(&schedulerPollFreqFlag, "scheduler-poll-frequency", 5000, "milliseconds between each poll while waiting for the scheduler")
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
	if extraVerboseFlag {
		verboseFlag = true
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
	case "wipe":
		err = wipe()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		flag.Usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %s\n", command, err)
		os.Exit(1)
	}
}
func wipe() error {
	conn, err := connect()
	if err != nil {
		return err
	}
	emptyConfig := make([]interface{}, 0)
	err = conn.putConfig(emptyConfig)
	if err != nil {
		return fmt.Errorf("failed to wipe config: %s", err)
	}
	if verboseFlag {
		fmt.Printf("Removed pipes and systems.\n")
	}
	empty := make(map[string]interface{})
	err = conn.putEnv(empty)
	if err != nil {
		return fmt.Errorf("failed to wipe environment variables: %s", err)
	}
	if verboseFlag {
		fmt.Printf("Removed environment variables.\n")
	}
	var datasets []Dataset
	err = conn.getDatasets(&datasets)
	if err != nil {
		return fmt.Errorf("failed to get list of datasets: %s", err)
	}
	for _, dataset := range datasets {
		if !strings.HasPrefix(dataset.Id, "system:") {
			err = conn.deleteDataset(dataset.Id)
			if err != nil {
				return fmt.Errorf("failed to delete dataset %s: %s", dataset.Id, err)
			}
		}
	}
	if verboseFlag {
		fmt.Printf("Removed datasets.\n")
	}
	return nil
}

func run() error {
	conn, err := connect()
	if err != nil {
		return err
	}

	if !customSchedulerFlag {
		err = addDefaultScheduler(conn)
		if err != nil {
			return err
		}
		defer removeDefaultScheduler(conn)
	}


	if verboseFlag {
		fmt.Printf("Loading scheduler.")
	}
	var systemStatus map[string]interface{}
	// wait for microservice to spin up
	for {
		if verboseFlag {
			fmt.Printf(".")
		}
		err = conn.getSystemStatus(schedulerIdFlag, &systemStatus)
		if err != nil {
			return err
		}
		if systemStatus["running"] == true {
			break
		}
		// wait 5 seconds before next poll
		time.Sleep(5000 * time.Millisecond)
	}
	if verboseFlag {
		fmt.Printf("done!\n")
	}

	if verboseFlag {
		fmt.Printf("Waiting for scheduler to respond idle without errors.")
	}

	var proxyStatus map[string]interface{}
	// wait for microservice to respond to requests without the node failing
	for {
		if verboseFlag {
			fmt.Printf(".")
		}
		err = conn.getProxyJson(schedulerIdFlag, "", &proxyStatus)
		if err == nil && proxyStatus["state"] == "init" {
			// no error and not started, microservice is ready
			break;
		}
		if extraVerboseFlag {
			if err != nil {
				fmt.Printf("(error)", err)
			} else {
				fmt.Printf("(previous container: %s)", proxyStatus["state"])
			}
		}
		// wait 5 seconds before next poll
		time.Sleep(5000 * time.Millisecond)
	}
	if verboseFlag {
		fmt.Printf("done!\n")
	}

	// start microservice using proxy api
	err = conn.postProxyNoBody(schedulerIdFlag, "start?reset_pipes=true&delete_datasets=true&compact_execution_datasets=true")
	if err != nil {
		return fmt.Errorf("failed to start scheduler: %s", err)
	}

	var printLog = func (since string) (string, error) {
		buf := new(bytes.Buffer)
		err := conn.getSystemLog(schedulerIdFlag, since, buf)
		if err != nil {
			return "", err
		}
		scanner := bufio.NewScanner(buf)
		for scanner.Scan() {
			line := scanner.Text();
			timestampedLine := strings.SplitN(line, " ", 2)
			since = timestampedLine[0]
			fmt.Println(timestampedLine[1])
		}
		return since, nil
	}
	// poll status api and display progress until finished or failed
	if verboseFlag {
		fmt.Printf("Running scheduler..")
	}
	if printSchedulerLogFlag {
		fmt.Println("--- BEGIN SCHEDULER LOG ---")
	}
	since := ""
	for {
		if printSchedulerLogFlag {
			// print the actual log instead of the dots..
			since, err = printLog(since)
			if err != nil {
				return err;
			}
		} else if verboseFlag {
			fmt.Printf(".")
		}
		err = conn.getProxyJson(schedulerIdFlag, "", &proxyStatus)
		if err != nil {
			return err
		}
		if proxyStatus["state"] == "success" {
			break
		}
		if proxyStatus["state"] == "failed" {
			return fmt.Errorf("scheduler failed, check the scheduler log (or run with -print-scheduler-log) and pipe execution datasets in the node")
		}
		time.Sleep(time.Duration(schedulerPollFreqFlag) * time.Millisecond)
	}
	if printSchedulerLogFlag {
		fmt.Println("--- END SCHEDULER LOG ---")
	} else if verboseFlag {
		fmt.Printf("done!\n")
	}
	return nil
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

func processOutputPipes(conn *connection, handler pipeHandler) error {
	var pipes []Pipe
	err := conn.getPipes(&pipes)
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

func getSpecs(conn *connection, update bool) ([]*testSpec, error) {
	files, err := ioutil.ReadDir(filepath.Join(conn.Basedir, "./expected"))
	if err != nil {
		return nil, fmt.Errorf("failed to scan expected dir, does it exist?: %s", err)
	}
	pipes := make(map[string]bool)
	err = processOutputPipes(conn, func(conn *connection, pipe *Pipe) error {
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
			spec, err := loadSpec(conn.Basedir, f.Name())
			if err != nil {
				return nil, fmt.Errorf("failed to load spec %s: %s", f.Name(), err)
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
			spec, err := createMissingSpec(conn.Basedir, pipe)
			if err != nil {
				return nil, err
			}
			specs = append(specs, spec)
		}
	}
	return specs, nil
}

func createMissingSpec(basedir string, pipe string) (*testSpec, error) {
	if verboseFlag {
		log.Printf("Creating missing placeholder test spec for pipe: %s", pipe)
	}
	specName := filepath.Join(basedir, "expected", fmt.Sprintf("%s.test.json", pipe))
	err := ioutil.WriteFile(specName, []byte("{\n}\n"), 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create missing spec file: %s", err)
	}
	spec, err := loadSpec(basedir, fmt.Sprintf("%s.test.json", pipe))
	if err != nil {
		return nil, err
	}
	return spec, nil
}

func handleSingle(conn *connection, spec *testSpec, update bool) error {
	if verboseFlag {
		fmt.Printf("Running test: %s\n", spec.Id)
	}
	// TODO store actual output if debugFlag is enabled and tests fails
	file := filepath.Join(conn.Basedir, "expected", spec.File)
	if spec.Ignore {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
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
			var bytes []byte
			if len(entities) == 0 {
				// empty array is serialized to null because empty array is and nil is the same
				bytes = []byte("[]")
			} else {
				bytes, _ = json.MarshalIndent(entities, "", "  ")
			}
			// append newline (old tool used to do that)
			bytes = append(bytes, byte('\n'))
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
	default:
		actual, err := conn.getPub(spec.Pipe, spec.Parameters, spec.Endpoint)
		if err != nil {
			return fmt.Errorf("failed to get data for %s: %s", spec.Pipe, err)
		}

		if spec.Endpoint == "xml" {
			doc := etree.NewDocument()
			if err := doc.ReadFromBytes(actual); err != nil {
				return err
			}
			doc.Indent(2)
			actual, err = doc.WriteToBytes()
			if err != nil {
				return err
			}
		}

		if update {
			err = ioutil.WriteFile(file, actual, 0644)
			if err != nil {
				return fmt.Errorf("failed to updated expected file %s: %s", file, err)
			}
			return nil
		} else {
			expected, err := ioutil.ReadFile(file)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(actual, expected) {
				return fmt.Errorf("content mismatch: expected %s got %s", expected, actual)
			}
			return nil
		}
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
		if _, err := os.Stat(filepath.Join(conn.Basedir, "expected", testFile)); os.IsNotExist(err) {
			if !update {
				return nil, fmt.Errorf("no test spec: %s", testFile)
			}
			spec, err = createMissingSpec(conn.Basedir, singlePipeFlag)

			if err != nil {
				return nil, err
			}
		}
		spec, err = loadSpec(conn.Basedir, testFile)
		if err != nil {
			return nil, err
		}
		err = handleSingle(conn, spec, update)
		if err != nil {
			return []error{fmt.Errorf("%s: %s", singlePipeFlag, err)}, nil
		}
		return []error{}, nil
	}
	specs, err := getSpecs(conn, update)
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
	} else {
		fmt.Printf("All tests passed!\n")
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

func loadSpec(basedir string, f string) (*testSpec, error) {
	// defaults
	name := strings.TrimSuffix(f, ".test.json")
	spec := testSpec{
		Id:     name,
		File:   fmt.Sprintf("%s.json", name),
		Endpoint: "json",
		Pipe:   name,
	}
	raw, err := ioutil.ReadFile(filepath.Join(basedir, "expected", f))
	if err != nil {
		return nil, err
	}
	// remove BOM
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
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
				if extraVerboseFlag {
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

	// clean up system if still present
	if !customSchedulerFlag {
		var system map[string]interface{}
		if extraVerboseFlag {
			log.Printf("Checking if scheduler %s was left in the node", schedulerIdFlag)
		}
		err := conn.getSystem(schedulerIdFlag, &system)
		if err != nil {
			return fmt.Errorf("failed to get scheduler system, aborting: %s", err)
		}
		if _, ok := system["_id"]; ok {
			err := removeDefaultScheduler(conn)
			if err != nil {
				return fmt.Errorf("failed to remove scheduler: %s", err)
			}
		}
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

	err = rmFiles(conn.Basedir, func(path string) (bool, error) {
		return strings.HasSuffix(path, ".conf.json"), nil
	})
	err = unzipTo(tmp.Name(), conn.Basedir)
	if err != nil {
		return err
	}
	fmt.Printf("Local config replaced by node config.\n")
	return nil
}

func clean() error {
	conn, err := connect()
	if err != nil {
		return err
	}
	dir := filepath.Join(conn.Basedir, buildDir)
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
	byte, err := ioutil.ReadFile(filepath.Join(conn.Basedir, profileFile))
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

	buf, err := zipConfig(conn.Basedir)

	if dumpFlag {
		fmt.Println("Dumping zip-")
		err = ioutil.WriteFile("upload.zip", buf.Bytes(), 0644)
		if err != nil {
			return err
		}
	}

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

func removeDefaultScheduler(conn *connection) error {
	if verboseFlag {
		log.Printf("Removing scheduler: %s", schedulerIdFlag)
	}
	err := conn.deleteSystem(schedulerIdFlag)
	if err != nil {
		return fmt.Errorf("failed to remove scheduler: %s", err)
	}
	return nil
}

func addDefaultScheduler(conn *connection) error {
	var scheduler []interface{}
	err := json.Unmarshal([]byte(fmt.Sprintf(`
[{
 "_id": "%s",
 "type": "system:microservice",
 "docker": {
  "environment": {
    "JWT": "%s",
    "URL": "%s",
    "DUMMY": "%s"
   },
  "image": "%s",
  "port": %d
 }
}]
`, schedulerIdFlag, conn.Jwt, conn.Node, uuid.NewV4(), schedulerImage, schedulerPort)), &scheduler)
	if err != nil {
		return err
	}
	if extraVerboseFlag {
		log.Printf("Scheduler:g %s", scheduler)
	}

	err = conn.postSystems(scheduler)
	if err != nil {
		return fmt.Errorf("failed to create scheduler: %s", err)
	}
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

	dir := filepath.Join(conn.Basedir, buildDir, "status")
	err = os.RemoveAll(dir)
	if err != nil {
		return err
	}

	local := filepath.Join(dir, "local")

	err = prepDiff(local, func(dst *os.File) error {
		buf, err := zipConfig(conn.Basedir)
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

type pathMatchFunc func(path string) (bool, error)

func rmFiles(dir string, matcher pathMatchFunc) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		match, err := matcher(path)
		if err != nil {
			return nil;
		}
		if !match {
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
	if extraVerboseFlag {
		log.Printf("walking %s to find config", src);
	}
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		match, err := matcher(p);
		if err != nil {
			return err;
		}
		if !match {
			return nil
		}
		relpath, err := filepath.Rel(src, p)
		if err != nil {
			return fmt.Errorf("unable to create relative zip path: %s", err);
		}
		f, err := w.Create(relpath)
		if err != nil {
			return err
		}
		s, err := os.Open(p)
		if err != nil {
			return err
		}
		written, err := io.Copy(f, s)
		if err != nil {
			return err
		}
		if verboseFlag {
			log.Printf("Added %s (%d bytes written)\n", p, written)
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

func zipConfig(basedir string) (*bytes.Buffer, error) {
	return zipDir(basedir, func(path string) (bool, error) {
		relPath, err := filepath.Rel(basedir, path)
		if err != nil {
			return false, err
		}
		if relPath == "node-metadata.conf.json" {
			return true, nil
		}
		if !strings.HasPrefix(relPath, "pipes") && !strings.HasPrefix(relPath, "systems") {
			return false, nil
		}
		return strings.HasSuffix(relPath, ".conf.json"), nil
	})
}

type connection struct {
	Jwt, Node, Basedir string
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

func loadSyncConfig(dir string) (*os.File, error) {
	config := ".syncconfig"
	if extraVerboseFlag {
		fmt.Printf("Checking directory: %s\n", dir);
	}
	file, err := os.Open(filepath.Join(dir, config))
	if err != nil {
		if os.IsNotExist(err) {
			parent, _ := filepath.Split(dir)
			if parent != "" && parent != string(os.PathSeparator) {
				return loadSyncConfig(parent)
			}
			return nil, fmt.Errorf("unable to locate %s in any parent directory", config)
		}
		return nil, fmt.Errorf("unable to %s: %s", config, err)
	}
	if extraVerboseFlag {
		fmt.Printf("Found %s in %s.\n", config, dir);
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

// loads connection from .syncconfig in current directory or closest parent directory if not overridden by env variables
func connect() (*connection, error) {
	r := &parseResult{}
	workDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("unable to get working directory %s", err)
	}
	f, err := loadSyncConfig(workDir)
	if err == nil {
		defer f.Close()
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
	baseDir := filepath.Dir(f.Name())
	if verboseFlag {
		fmt.Printf("Using %s as base directory.\n", baseDir)
	}
	return &connection{Jwt: cleanJwt(jwt), Node: fixNodeUrl(node), Basedir: baseDir}, nil
}

func (conn *connection) doRequest(r *http.Request) (*http.Response, error) {
	resp, err := conn.doRawRequest(r)
	if err != nil {
		return nil, err
	}
	err = assert2xx(resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// do request without asserting response code
func (conn *connection) doRawRequest(r *http.Request) (*http.Response, error) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLSVerifyFlag},
	}

	client := &http.Client{Transport: tr}
	r.Header.Add("Authorization", fmt.Sprintf("bearer %s", conn.Jwt))
	if extraVerboseFlag {
		log.Printf("%v: %v\n", r.Method, r.URL)
	}
	resp, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("unable to do request: %v", err)
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func assert2xx(resp *http.Response) error {
	var debugErrorResponse = func() {
		if extraVerboseFlag {
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(resp.Body)
			if err == nil {
				fmt.Printf("got response body: %s", buf.String())
			}
		}
	}

	if resp.StatusCode == 500 {
		debugErrorResponse();
		return fmt.Errorf("node failed (got 500), check the node log for possible bugs? %s", resp.Status)
	}
	if resp.StatusCode == 403 {
		debugErrorResponse();
		return fmt.Errorf("failed to talk to the node (got HTTP 403 Forbidden), maybe the JWT has expired? %s", resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		debugErrorResponse();
		return fmt.Errorf("expected http status code 2xx, got: %d (%s)", resp.StatusCode, resp.Status)
	}
	return nil
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

type Dataset struct {
	Id string `json:"_id"`
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

func (conn *connection) getDatasets(target *[]Dataset) error {
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/datasets", conn.Node), nil)
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

func (conn *connection) putConfig(config []interface{}) error {
	b, err := json.Marshal(config)
	if err != nil {
		return err
	}
	r, err := http.NewRequest("PUT", fmt.Sprintf("%s/config?force=true", conn.Node), bytes.NewBuffer(b))
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

func (conn *connection) putZipConfig(zip *bytes.Buffer) error {
	r, err := http.NewRequest("PUT", fmt.Sprintf("%s/config?force=true", conn.Node), zip)
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

func (conn *connection) getPub(pipe string, parameters map[string]string, pub string) ([]byte, error) {
	v := url.Values{}
	for k, p := range parameters {
		v.Add(k, p)
	}
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/publishers/%s/%s?%s", conn.Node, pipe, pub, v.Encode()), nil)
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

func (conn *connection) putSecrets(env interface{}) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	r, err := http.NewRequest("PUT", fmt.Sprintf("%s/secrets", conn.Node), bytes.NewBuffer(b))
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

func (conn *connection) deleteSystem(system string) error {
	r, err := http.NewRequest("DELETE", fmt.Sprintf("%s/systems/%s", conn.Node, system), nil)
	if err != nil {
		// shouldn't happen if connection is sane
		return fmt.Errorf("unable to create request: %v", err)
	}
	_, err = conn.doRequest(r)
	if err != nil {
		return err
	}
	return nil
}

func (conn *connection) deleteDataset(dataset string) error {
	r, err := http.NewRequest("DELETE", fmt.Sprintf("%s/datasets/%s", conn.Node, dataset), nil)
	if err != nil {
		// shouldn't happen if connection is sane
		return fmt.Errorf("unable to create request: %v", err)
	}
	_, err = conn.doRequest(r)
	if err != nil {
		return err
	}
	return nil
}

func (conn *connection) postSystems(systems []interface{}) error {
	b, err := json.Marshal(systems)
	if err != nil {
		return err
	}
	r, err := http.NewRequest("POST", fmt.Sprintf("%s/systems", conn.Node), bytes.NewBuffer(b))
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

func (conn *connection) postProxyNoBody(system string, subUrl string) error {
	r, err := http.NewRequest("POST", fmt.Sprintf("%s/systems/%s/proxy/%s", conn.Node, system, subUrl), nil)
	if err != nil {
		// shouldn't happen if connection is sane
		return fmt.Errorf("unable to create request: %v", err)
	}
	_, err = conn.doRequest(r)
	if err != nil {
		return err
	}
	return nil
}


func (conn *connection) getSystemStatus(system string, target interface{}) error {
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/systems/%s/status", conn.Node, system), nil)
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

func (conn *connection) getProxyJson(system string, subUrl string, target interface{}) error {
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/systems/%s/proxy/%s", conn.Node, system, subUrl), nil)
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

func (conn *connection) getSystem(system string, target interface{}) error {
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/systems/%s", conn.Node, system), nil)
	if err != nil {
		// shouldn't happen if connection is sane
		return fmt.Errorf("unable to create request: %v", err)
	}

	resp, err := conn.doRawRequest(r)
	if err != nil {
		return err
	}
	if resp.StatusCode == 404 {
		return nil
	}
	err = assert2xx(resp)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}

func (conn *connection) getSystemLog(system string, since string, target io.Writer) error {
	v := url.Values{}
	if since != "" {
		v.Add("since", since)
	}
	r, err := http.NewRequest("GET", fmt.Sprintf("%s/systems/%s/logs?%s", conn.Node, system, v.Encode()), nil)
	if err != nil {
		// shouldn't happen if connection is sane
		return fmt.Errorf("unable to create request: %v", err)
	}

	resp, err := conn.doRequest(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(target, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read log: %s", err);
	}
	return nil;
}
