FROM ubuntu as zstd-builder

RUN apt-get update && apt-get update -y && apt-get install -y make gcc libc-dev git

RUN git clone https://github.com/facebook/zstd src

RUN mkdir /pkg && cd /src && make && make DESTDIR=/pkg install

# Second minimal image to only keep the built binary
#FROM electrotumbao/golang-protoc as go-builder
FROM golang as go-builder

ADD . /go/src/github.com/m-lab/tcp-info
WORKDIR /go/src/github.com/m-lab/tcp-info

# List all of the go imports, excluding any in this repo, and run go get to import them.
RUN go get -u -v $(go list -f '{{join .Imports "\n"}}{{"\n"}}{{join .TestImports "\n"}}' ./... | sort | uniq | grep -v m-lab/tcp-info)
RUN go get github.com/golang/protobuf/protoc-gen-go/ github.com/golang/protobuf/proto

# Install all go executables.  Creates all build targets in /go/bin directory.
RUN go install -v ./...

# Must keep this the same as the zstd-builder env until we figure out how to
# make the zstd binary comile as a static binary.
# TODO: Make zstd compile as a static binary.
FROM ubuntu

# Copy the built files (from /pkg/usr/local/bin)
COPY --from=zstd-builder /pkg /

# Copy the license as well
RUN mkdir -p /usr/local/share/licenses/zstd
COPY --from=zstd-builder /src/LICENSE /usr/local/share/licences/zstd/

COPY --from=go-builder /go/bin /usr/local/bin

EXPOSE 9090 8080

# TODO - Make the destination directory flag controlled.
# Probably should default to /data
WORKDIR /home

ENTRYPOINT ["/usr/local/bin/tcp-info"]
