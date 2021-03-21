package twistedElgamal

import (
	"ZKSneak-crypto/ecc/zp256"
	"github.com/magiconair/properties/assert"
	"math/big"
	"testing"
)

func TestEncDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(100000)
	r := zp256.RandomValue()
	enc := Enc(b, r, pk)
	dec := Dec(enc, sk)
	//assert.Equal(t, b, dec)
	assert.Equal(t, b, dec)
}
