# Sesam Client

[![Build Status](https://travis-ci.org/sesam-io/sesam.svg?branch=master)](https://travis-ci.org/sesam-io/sesam)

Sesam command tool to use with [Sesam](https://sesam.io) The Hybrid Data Hub iPaaS.
  
## Usage

```
$ sesam clean
$ sesam upload
Node config replaced with local config.
## edit stuff in Sesam Management Studio
$ sesam download
Local config replaced by node config.
$ sesam status
Node config is up-to-date with local config.
$ sesam record
Current output stored as expected output.
$ sesam verify
Verifying output...passed!
$ sesam verify-stable
Verifying stable output (3/3)...passed!
```

## Installing

Prebuild binaries for common platforms can be downloaded from [Github Releases](https://github.com/sesam-io/sesam/releases/).

## Building from source

1. Install [Go](https://golang.org)
2. Make sure GOPATH is set and PATH includes $GOPATH/bin
3. Download and build the package:
 ```
 $ go get github.com/sesam-io/sesam
 ```
4. Verify that it works
```
$ sesam -version
0.0.8
```


