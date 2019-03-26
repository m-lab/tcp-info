# An image for building zstd
FROM ubuntu as builder

# Get zstd source and compile zstd as a static binary.
RUN apt-get update && apt-get update -y && apt-get install -y make gcc libc-dev git
RUN git clone https://github.com/facebook/zstd src
RUN mkdir /pkg && cd /src && make MOREFLAGS="-static" zstd && make DESTDIR=/pkg install


# Build tcp-info
FROM golang:1.12.1-stretch as go-builder

# Add the tcp-info code from the local repo.
ADD . /go/src/github.com/m-lab/tcp-info
WORKDIR /go/src/github.com/m-lab/tcp-info

# Get all of our imports, including test imports.
RUN go get -v -t ./...

# Install all go executables.  Creates all build targets in /go/bin directory.
RUN go install -v ./...


# Build the image containing both binaries.
FROM alpine

# Copy the zstd binary and license.
COPY --from=builder /pkg/usr/local/bin/zstd /bin/zstd
RUN mkdir -p /licenses/zstd
COPY --from=builder /src/LICENSE /licences/zstd/

# Copy the tcp-info binary.
COPY --from=builder /go/bin/tcp-info /bin/tcp-info

# TODO - Make the destination directory flag controlled.
# Probably should default to /var/spool/tcp-info/
WORKDIR /home

ENTRYPOINT ["/bin/tcp-info"]
