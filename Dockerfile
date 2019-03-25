# Build the go code.
FROM golang:1.12.1-stretch as go-builder
RUN apt-get update && apt-get install -y zstd

ADD . /go/src/github.com/m-lab/tcp-info
WORKDIR /go/src/github.com/m-lab/tcp-info

# List all of the go imports, excluding any in this repo, and run go get to import them.
RUN go get -v -t ./...

# Install all go executables.  Creates all build targets in /go/bin directory.
RUN go install -v ./...

# Run all the unit tests, to make sure they work in context.
RUN go test ./...


# Must keep this the same as the zstd-builder env until we figure out how to
# make the zstd binary comile as a static binary.
# TODO: Make zstd compile as a static binary.
FROM ubuntu
RUN apt-get update && apt-get install -y zstd

COPY --from=go-builder /go/bin /usr/local/bin

EXPOSE 9090 8080

# TODO - Make the destination directory flag controlled.
# Probably should default to /data
WORKDIR /home

ENTRYPOINT ["/usr/local/bin/tcp-info"]
