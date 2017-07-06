#!/bin/bash
set -x
TAG=$TRAVIS_TAG
mkdir -p dist
GOOS=windows GOARCH=amd64 go build -o sesam.exe main.go
zip dist/sesam$TAG.windows-amd64.zip sesam.exe
rm sesam.exe
GOOS=darwin GOARCH=amd64 go build -o sesam main.go
tar -zcf dist/sesam$TAG.darwin-amd64.tar.gz sesam
rm sesam
GOOS=linux GOARCH=amd64 go build -o sesam main.go
tar -zcf dist/sesam$TAG.linux-amd64.tar.gz sesam
rm sesam
