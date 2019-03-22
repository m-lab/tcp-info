# Protobuf compiler details:

To resolve problems with pb.go files, you generally will need to recompile the
.proto files on your local machine, using the appropriate versions of the golang
protobuf library, and protoc compiler.

As of March 2019, the travis build always uses the latest version of the golang
protoc-gen-go repo.  To get the latest version, use:

```bash
go get -d -u github.com/golang/protobuf/protoc-gen-go
go install github.com/golang/protobuf/protoc-gen-go
```

As of March 2019, the travis build uses the v3.7.0 version of the protobuf
compiler.  To install in your local project, use:

```bash
wget https://github.com/google/protobuf/releases/download/v3.7.0/protoc-3.6.0-linux-x86_64.zip
unzip protoc-3.6.0-linux-x86_64.zip  # Should provide bin/protoc
bin/protoc --version
```

Then, make sure you use this compiler to locally compile the .proto files, and
commit to your branch.  From the repository root, use:

```bash
./bin/protoc --go_out=. nl-proto/*.proto
```

It may be useful to look for the version spec in the pb.go files.

```bash
find . -name "*.pb.go" | xargs grep IsVersion
```

If this is different in the repo, vs in the compiles pb.go file compiled by travis,
it means you likely need to upgrade the golang/protobuf code generator.
