# tcp-info

[![GoDoc](https://godoc.org/github.com/m-lab/tcp-info?status.svg)](https://godoc.org/github.com/m-lab/tcp-info) [![Build Status](https://travis-ci.org/m-lab/tcp-info.svg?branch=master)](https://travis-ci.org/m-lab/tcp-info) [![Go Report Card](https://goreportcard.com/badge/github.com/m-lab/tcp-info)](https://goreportcard.com/report/github.com/m-lab/tcp-info) [![Coverage Status](https://coveralls.io/repos/m-lab/tcp-info/badge.svg?branch=master)](https://coveralls.io/github/m-lab/tcp-info?branch=master)

The `tcp-info` tool executes a polling loop that tracks the measurement statistics of every open TCP socket on a system.  Data is written, in `jsonl` format, to files compressed using `zstd`.  This tool forms the basis of a lot of measurements on the Kubernetes-based [Measurement Lab](https://measurementlab.net) platform.

<<<<<<< HEAD
We expect most people will run this tool using a
docker container.  To invoke, with data written to ~/data, and prometheus
metrics published on port 7070:

```bash
docker run --network=host -v ~/data:/home/ -it measurementlab/tcp-info -prom=7070
```

If you want to use this tool outside of a container, then you will also require
`zstd`, which can be installed with:
=======
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
>>>>>>> 489c6ec... Update README.md

```bash
sudo apt-get update && sudo apt-get install -y zstd
```
<<<<<<< HEAD
=======


To invoke, with data written to ~/data, and prometheus metrics published on port
7070:
```bash
docker run --network=host -v ~/data:/home/ -it measurementlab/tcp-info -prom=7070
```

# Code Layout

The code needs a bit of restructuring at this point.  Ideally it should look like:

* inetdiag - Should contain ONLY the code related to include/uapi/linux/inet_diag.h
* tcp - Should include ONLY the code related to include/uapi/linux/tcp.h
* netlink - Should include ONLY code related to using the netlink syscall and handling syscall.NetlinkMessage.  It might have a dependency on inetdiag.
* parsing - Should include code related to parsing the messages in inetdiag and tcp.
* zstd - Already fine.  Contains just zstd reader and writer code.
* saver, cache, collector - already fine.

>>>>>>> 489c6ec... Update README.md
