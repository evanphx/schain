package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/zalando/go-keyring"
)

const (
	KeyringService = "schain"
	KeyringUser    = "schain"
	Dir            = ".schain"
)

func filePath(name string) string {
	dir := os.Getenv("SCHAIN_DIR")
	var path string

	if dir != "" {
		path = filepath.Join(dir, name)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}

		path = filepath.Join(home, Dir, name)
	}

	os.MkdirAll(filepath.Dir(path), 0755)

	return path
}

var enc = base64.RawURLEncoding

func setupKey() []byte {
	user := os.Getenv("SCHAIN_KEY")
	if user == "" {
		user = KeyringUser
	}

	skey, err := keyring.Get(KeyringService, user)
	if err != nil {
		if err != keyring.ErrNotFound {
			log.Fatal(err)
		}
	} else {
		key, err := enc.DecodeString(skey)
		if err != nil {
			log.Fatal(err)
		}

		return key
	}

	// Ok, make a new key

	key := make([]byte, chacha20poly1305.KeySize)

	_, err = io.ReadFull(rand.Reader, key)
	if err != nil {
		log.Fatal(err)
	}

	err = keyring.Set(KeyringService, user, enc.EncodeToString(key))
	if err != nil {
		log.Fatal(err)
	}

	return key
}

func set() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: schain -s chain\n")
		os.Exit(1)
	}

	key := setupKey()

	c, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}

	chain := os.Args[2]

	path := filePath(chain)

	var data []byte

	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatal(err)
		}
	} else {

		nonce := make([]byte, c.NonceSize())

		_, err = io.ReadFull(f, nonce)
		if err != nil {
			log.Fatal(err)
		}

		ciphertext, err := ioutil.ReadAll(f)
		if err != nil {
			log.Fatal(err)
		}

		f.Close()

		data, err = c.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Fatal(err)
		}
	}

	br := bufio.NewReader(os.Stdin)

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)

		if len(line) == 0 {
			break
		}

		idx := strings.IndexByte(line, '=')
		if idx == -1 {
			log.Fatalln("Input format must be NAME=VALUE")
		}

		data = append(data, line...)
		data = append(data, '\n')
	}

	nonce := make([]byte, c.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext := c.Seal(nil, nonce, data, nil)

	err = ioutil.WriteFile(path, append(nonce, ciphertext...), 0600)
	if err != nil {
		log.Fatal(err)
	}
}

func get() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: schain chain command...\n")
		os.Exit(1)
	}

	key := setupKey()

	c, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}

	chain := os.Args[1]

	path := filePath(chain)

	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}

	env := os.Environ()

	nonce := make([]byte, c.NonceSize())

	_, err = io.ReadFull(f, nonce)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, err := ioutil.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}

	data, err := c.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatalln("Unable to decrypt chain, perhaps key was changed")
	}

	br := bufio.NewReader(bytes.NewReader(data))

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

func export() {
	key := setupKey()
	fmt.Println(enc.EncodeToString(key))
}

func main() {
	switch os.Args[1] {
	case "-s":
		set()
	case "--export":
		export()
	default:
		get()
	}
}
