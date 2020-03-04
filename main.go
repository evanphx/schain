package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: ec chain command...\n")
		os.Exit(1)
	}

	chain := os.Args[1]

	path := filepath.Join(home, ".keychains", chain)

	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}

	env := os.Environ()

	br := bufio.NewReader(f)

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)

		idx := strings.IndexByte(line, '=')
		if idx != -1 {
			env = append(env, line)
		}
	}

	f.Close()

	execpath, err := exec.LookPath(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to find command: %s\n", os.Args[2])
		os.Exit(1)
	}

	err = syscall.Exec(execpath, os.Args[2:], env)
	log.Fatal(err)
}
