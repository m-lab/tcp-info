package main

import (
	"log"
	"os"

	"github.com/gocarina/gocsv"
	"github.com/m-lab/tcp-info/loader"
	"github.com/m-lab/tcp-info/parse"
)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	// TODO handle gs: and local filenames.

	// TODO filter a single file from a tar file.

	// Read input from stdin.

	rdr := loader.NewInetReader(os.Stdin)

	wrappers := make([]*parse.Wrapper, 0, 3000)
	for {
		wrapper, err := rdr.Next()
		if err != nil {
			log.Println(err)
			break
		}
		wrappers = append(wrappers, wrapper)
	}

	wrappers[0].Metadata = &parse.Metadata{}

	err := gocsv.Marshal(wrappers, os.Stdout)
	if err != nil {
		log.Println(err)
	}

	// Write output to stdout.
}
