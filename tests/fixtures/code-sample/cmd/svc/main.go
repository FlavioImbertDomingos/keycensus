package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func main() {
	k, _ := rsa.GenerateKey(rand.Reader, 3072)
	e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	m, _ := mlkem.GenerateKey768()
	fmt.Println(k.N.BitLen(), e.Curve.Params().Name, x.PublicKey(), len(m.EncapsulationKey().Bytes()),
		md5.Sum([]byte("a")), sha256.Sum256([]byte("b")))
}
