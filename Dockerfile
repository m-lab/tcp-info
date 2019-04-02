# An image for building zstd
FROM ubuntu as zstd-builder

# Get zstd source and compile zstd as a static binary.
RUN apt-get update && apt-get update -y && apt-get install -y make gcc libc-dev git
RUN git clone https://github.com/facebook/zstd src
RUN mkdir /pkg && cd /src && make MOREFLAGS="-static" zstd && make DESTDIR=/pkg install


# An image for building tcp-info
FROM golang:1.12 as tcp-info-builder

ENV CGO_ENABLED 0

# Add the tcp-info code from the local repo.
ADD . /go/src/github.com/m-lab/tcp-info
WORKDIR /go/src/github.com/m-lab/tcp-info

# Get all of our imports and compile the tcp-info binary into /go/bin
RUN go get -v \
      -ldflags "-X github.com/m-lab/go/prometheusx.GitShortCommit=$(git log -1 --format=%h)" \
      .

# Build the image containing both binaries.
FROM alpine

# Copy the zstd binary and license.
COPY --from=zstd-builder /pkg/usr/local/bin/zstd /bin/zstd
RUN mkdir -p /licenses/zstd
COPY --from=zstd-builder /src/LICENSE /licences/zstd/

# Copy the tcp-info binary.
COPY --from=tcp-info-builder /go/bin/tcp-info /bin/tcp-info

# This WORKDIR should be mostly unused, because the tcp-info binary takes a
# flag of the form --output=dir, and we expect all users should pass in that
# flag.
WORKDIR /home

ENTRYPOINT ["/bin/tcp-info"]
