# tcp-info
![GoDoc](https://godoc.org/github.com/m-lab/tcp-info?status.svg)] [![Build Status](https://travis-ci.org/m-lab/tcp-info.svg?branch=master)](https://travis-ci.org/m-lab/tcp-info) [![Go Report Card](https://goreportcard.com/badge/github.com/m-lab/tcp-info)](https://goreportcard.com/report/github.com/m-lab/tcp-info) [![Coverage Status](https://coveralls.io/repos/m-lab/tcp-info/badge.svg?branch=master)](https://coveralls.io/github/m-lab/tcp-info?branch=master)

The `tcp-info` tool executes a polling loop that tracks the measurement statistics of every open TCP socket on a system.  Data is written, in `jsonl` format, to files compressed using `zstd`.  This tool forms the basis of a lot of measurements on the Kubernetes-based [Measurement Lab](https://measurementlab.net) platform.

We expect most people will run this tool using a
docker container.  To invoke, with data written to ~/data, and prometheus
metrics published on port 7070:
```bash
docker run --network=host -v ~/data:/home/ -it measurementlab/tcp-info -prom=7070
```

If you want to use this tool outside of a container, then you will also require
`zstd`, which can be installed with:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/horta/zstd.install/master/install)
```

