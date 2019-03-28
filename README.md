# tcp-info

[![GoDoc](https://godoc.org/github.com/m-lab/tcp-info?status.svg)](https://godoc.org/github.com/m-lab/tcp-info) [![Build Status](https://travis-ci.org/m-lab/tcp-info.svg?branch=master)](https://travis-ci.org/m-lab/tcp-info) [![Go Report Card](https://goreportcard.com/badge/github.com/m-lab/tcp-info)](https://goreportcard.com/report/github.com/m-lab/tcp-info) [![Coverage Status](https://coveralls.io/repos/m-lab/tcp-info/badge.svg?branch=master)](https://coveralls.io/github/m-lab/tcp-info?branch=master)

The `tcp-info` tool executes a polling loop that tracks the measurement statistics of every open TCP socket on a system.  Data is written, in `jsonl` format, to files compressed using `zstd`.  This tool forms the basis of a lot of measurements on the Kubernetes-based [Measurement Lab](https://measurementlab.net) platform.

We expect most people will run this tool using a
docker container.  To invoke, with data written to ~/data, and prometheus
metrics published on port 7070:

```bash
docker run --network=host -v ~/data:/home/ -it measurementlab/tcp-info -prom=7070
```

# Fast tcp-info collector in Go

This repository uses the netlink API to collect inet_diag messages, partially parses them, caches the intermediate representation.
It then detects differences from one scan to the next, and queues connections that have changed for logging.
It logs the intermediate representation through external zstd processes to one file per connection.

The previous version uses protobufs, but we have discontinued that largely because of the increased maintenance overhead, and risk of losing unparsed data.

To run the tests or the collection tool, you will also require zstd, which can be installed with:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/horta/zstd.install/master/install)
```

OR

```bash
sudo apt-get update && sudo apt-get install -y zstd
```

# Code Layout

* inetdiag - code related to include/uapi/linux/inet_diag.h.  All structs will be in structs.go
* tcp - Should include ONLY the code related to include/uapi/linux/tcp.h
* parse - code related to parsing the messages in inetdiag and tcp.
* zstd - zstd reader and writer.
* saver - code related to writing ParsedMessages to files.
* cache - code to cache netlink messages and detect changes.
* collector - code related to collecting netlink messages from the kernel.

## Dependencies (as of March 2019)

* saver: inetdiag, cache, parse, tcp, zstd
* collector: parse, saver, inetdiag, tcp
* main.go: collector, saver, parse (just for sanity check)
* cache: parse
* parse: inetdiag

And (almost) all package use metrics.

### Layers (each layer depends only on items to right, or lower layers)
1. main.go
1. collector > saver > cache > parse
1. inetdiag, tcp, zstd, metrics
