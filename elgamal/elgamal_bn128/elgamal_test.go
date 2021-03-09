package elgamal_bn128

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(100000)
	r, _ := rand.Int(rand.Reader, ORDER)
	bEnc := Enc(b, r, pk)
	bDec := Dec(bEnc, sk)
	fmt.Println(bDec)
}
