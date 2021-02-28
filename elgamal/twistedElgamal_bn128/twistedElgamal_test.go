package twistedElgamal_bn128

import (
	"crypto/rand"
	"fmt"
	"github.com/magiconair/properties/assert"
	"math/big"
	"testing"
)

func TestEncDec(t *testing.T) {
	sk, pk := GenKeyPair()
	fmt.Println("pk len:", len(pk.Bytes()))
	b := big.NewInt(int64(50000))
	r, _ := rand.Int(rand.Reader, ORDER)
	enc := Enc(b, r, pk)
	//dec := Dec(enc, sk)
	dec2 := DecByStart(enc, sk, 0)
	//assert.Equal(t, b, dec)
	assert.Equal(t, b, dec2)
}
