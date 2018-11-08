# tcp-info
| branch | travis-ci | report-card | coveralls |
|--------|-----------|-----------|-------------|
| master | [![Travis Build Status](https://travis-ci.org/m-lab/tcp-info.svg?branch=master)](https://travis-ci.org/m-lab/tcp-info) | [![Go Report Card](https://goreportcard.com/badge/github.com/m-lab/tcp-info)](https://goreportcard.com/report/github.com/m-lab/tcp-info) | [![Coverage Status](https://coveralls.io/repos/m-lab/tcp-info/badge.svg?branch=master)](https://coveralls.io/github/m-lab/tcp-info?branch=master) |



Fast tcp-info collector in Go

This repository uses protobuffers and zstd.  To build it locally you will need to install and run the protobuf
compiler:

```bash
wget https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip
unzip protoc-3.5.1-linux-x86_64.zip
cd nl-proto && ../bin/protoc --go_out=. *.proto
```

To run the collection tool, you will also require zstd, which can be installed with:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/horta/zstd.install/master/install)
```

To invoke, with data written to ~/data, and prometheus metrics published on port
7070:
```bash
docker run --network=host -v ~/data:/home/ -it measurementlab/tcp-info -prom=7070
```
