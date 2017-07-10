package main

import (
	"fmt"
	"flag"
)

var version string

func main() {
	versionPtr := flag.Bool("version", false, "print version number")
	nodePtr := flag.String("node", "http://localhost:9042/api", "service url")
	jwtPtr := flag.String("jwt", "", "authorization token")
	flag.Parse()
	if *versionPtr {
		// https://stackoverflow.com/questions/11354518/golang-application-auto-build-versioning
		fmt.Printf("sesam version %s\n", version)
		return
	}
	_ = nodePtr
	_ = jwtPtr

	args := flag.Args()
	if len(args) == 0 {
		// TODO add sub command Usage
		flag.Usage()
		return
	}
	switch args[0] {
	case "upload":
		upload()
	default:
		fmt.Printf("unknown command: %s\n", args[0])
		// TODO add sub command Usage
		flag.Usage()
	}
}

func upload() {
	fmt.Println("TODO upload")
}