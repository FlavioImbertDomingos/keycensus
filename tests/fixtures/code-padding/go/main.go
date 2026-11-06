package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func main() {
	k, _ := rsa.GenerateKey(rand.Reader, 3072)
	d := sha256.Sum256([]byte("m"))
	c, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &k.PublicKey, []byte("m"), nil)
	s, _ := rsa.SignPSS(rand.Reader, k, crypto.SHA256, d[:], nil)
	p, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	fmt.Println(len(c), len(s), len(p))
}
