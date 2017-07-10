# Sesam Client

[![Build Status](https://travis-ci.org/sesam-io/sesam.svg?branch=master)](https://travis-ci.org/sesam-io/sesam)

Sesam command tool to use with [Sesam](https://sesam.io) The Hybrid Data Hub iPaaS.

## Configuration
```
$ sesam init
Username: foo
Password:
Available subscriptions:
1. My dev node (11aa76...)
2. My test node (44bb11...)
Subscription to use? 2
Config stored in .sesam/config.
```

## Usage

Typical workflow:

```
$ sesam clean
$ sesam upload
Node config replaced with local config.
## edit stuff in Sesam Management Studio
$ sesam download
Local config replaced by node config.
$ sesam status
Node config is up-to-date with local config.
$ sesam run
Run completed.
$ sesam update
Current output stored as expected output.
$ sesam verify
Verifying output...passed!
```

Or run the full test cycle (typical CI setup):

```
$ sesam test
Node config replaced with local config.
Run completed.
Verifying output (1/3)...passed!
Run completed.
Verifying output (2/3)...passed!
Run completed.
Verifying output (3/3)...passed!
```

## Configuring tests

| Property | Description | Type | Required | Default |
|------------|----------------------------------------------------------------------------|------------------|----------|-----------------------------------------------------------------------|
| _id | Name of the test. | string | No | Name of the .test.json file |
| type | Config type so that this later can just be part of the rest of the config. | String | No | test |
| description | A description of test | string | No | |
| ignore | If the output should be ignored during tests | boolean | No | false |
| endpoint | If the output should be fetched from a published endpoint instead | string | No | By default the json is grabbed from ``/pipes/<my-pipe>/entities``
| file | File that contains the expected results | string | No | Name of the .test.json file without .test (e.g. foo.test.json looks for foo.json)
| blacklist | Which properties to ignore in the output. | Array of strings | No | [] |
| parameters | Which parameters to pass as bound parameters. Note that parameters only works for published endpoints. TODO verify this. | Object | No | |

Example: 
```
$ cat foo.test.json
{
  "_id": "foo",
  "type": "test",
  "file": "foo.json"
  "blacklist": ["my-timestamp"],
  "ignore": false
}
```

### DTL parameters

If you need to pass various variations of bound parameters to the DTL, you just create multiple .test.json files for each combination of parameters.

Example:
```
$ cat foo-A.test.json
{
  "_id": "foo",
  "type": "test",
  "file": "foo-A.json",
  "endpoint": "entities",
  "parameters": {
    "my-param": "A"
  }
}
$ cat foo-B.test.json
{
  "_id": "foo",
  "type": "test",
  "file": "foo-B.json",
  "endpoint": "entities",
  "parameters": {
    "my-param": "B"
  }
}
```
This will compare the output of ``/publishers/foo/entities?my-param=A`` with the contents of ``foo-A.json`` and ``/publishers/foo/entities?my-param=B`` with the contents of ``foo-B.json``.

### Endpoints

By default the entities are fetched from ``/pipes/<my-pipe>/entities``, but if endpoint is set it will be fetched from
``/publishers/<my-pipe>/<endpoint-type>`` based on the endpoint type specified. Note that the pipe needs to be configured to publish to this endpoint as well.
 
Example:
```
{
  "_id": "foo",
  "type": "test",
  "endpoint": "xml",
  "file": "foo.xml"
}
```
This will compare the output of ``/publishers/foo/xml`` with the contents of ``foo.xml``.

## Installing

Prebuild binaries for common platforms can be downloaded from [Github Releases](https://github.com/sesam-io/sesam/releases/).

## Building from source

1. Install [Go](https://golang.org)
2. Make sure ``GOPATH`` is set and ``PATH`` includes ``$GOPATH/bin``
3. Download and build the package:
 ```
 $ go get github.com/sesam-io/sesam
 ```
4. Verify that it works
```
$ sesam -version
sesam version 0.0.8
```


