package twistedElgamal_bn128

import (
	"crypto/rand"
	"github.com/magiconair/properties/assert"
	"math/big"
	"testing"
)

func TestEncDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(int64(1000000))
	r, _ := rand.Int(rand.Reader, ORDER)
	enc := Enc(b, r, pk)
	dec := Dec(enc, sk)
	assert.Equal(t, b, dec)
}
