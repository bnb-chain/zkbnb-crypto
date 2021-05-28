package twistedElgamal

import (
	"fmt"
	"github.com/magiconair/properties/assert"
	"math"
	"math/big"
	"testing"
	"zecrey-crypto/ecc/zp256"
)

func TestEncDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(10000)
	r := zp256.RandomValue()
	max := int64(math.Pow(2, 32))
	enc, _ := Enc(b, r, pk)
	bPrime, _ := Dec(enc, sk, max)
	fmt.Println(bPrime)
	//assert.Equal(t, b, dec)
	assert.Equal(t, b, bPrime)
}
