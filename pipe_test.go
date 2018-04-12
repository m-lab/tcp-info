package main

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"testing"
)

func TestPipeZstd(t *testing.T) {
	f, _ := os.Create("out.zst")
	cmd := exec.Command("zstd")
	raw := bytes.NewBufferString("foobar")
	cmd.Stdin = raw
	cmd.Stdout = f
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}

func TestPipeZstd2(t *testing.T) {
	pipe, wg := ZStdPipe("foobar.zst")
	pipe.WriteString("Foobar")
	pipe.Close()
	wg.Wait()

}
