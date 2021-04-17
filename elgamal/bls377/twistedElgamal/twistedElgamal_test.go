package twistedElgamal

import (
	"zecrey-crypto/ecc/zbls377"
	"github.com/magiconair/properties/assert"
	"math/big"
	"testing"
)

func TestEncDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(10000)
	r := zbls377.RandomValue()
	enc := Enc(b, r, pk)
	dec := Dec(enc, sk)
	//assert.Equal(t, b, dec)
	assert.Equal(t, b, dec)
}
