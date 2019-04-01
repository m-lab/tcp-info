package main

import (
	"log"
	"os"

	"github.com/gocarina/gocsv"
	"github.com/m-lab/tcp-info/loader"
	"github.com/m-lab/tcp-info/netlink"
	"github.com/m-lab/tcp-info/parse"
)

func init() {
	// Always prepend the filename and line number.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// TODO handle gs: and local filenames.
// TODO filter a single file from a tar file.
func main() {

	// Read input from stdin.
	rdr := loader.NewInetReader(os.Stdin)

	// Read all the ParsedMessage and convert to Wrappers.
	wrappers := make([]*parse.Wrapper, 0, 3000)
	for {
		wrapper, err := rdr.Next()
		if err != nil {
			log.Println(err)
			break
		}
		wrappers = append(wrappers, wrapper)
	}

	wrappers[0].Metadata = &netlink.Metadata{}

	// Write output to stdout.
	err := gocsv.Marshal(wrappers, os.Stdout)
	if err != nil {
		log.Println(err)
	}

}
