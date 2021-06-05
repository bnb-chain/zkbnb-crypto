package twistedElgamal

import (
	"fmt"
	"github.com/magiconair/properties/assert"
	"math"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

func TestEncDec(t *testing.T) {
	sk, pk := GenKeyPair()
	b := big.NewInt(1000)
	delta := big.NewInt(-500)
	r := curve.RandomValue()
	max := int64(math.Pow(2, 32))
	enc, _ := Enc(b, r, pk)
	encDelta, _ := Enc(delta, r, pk)
	encAdd, _ := EncAdd(enc, encDelta)
	bDelta, _ := Dec(encAdd, sk, max)
	fmt.Println(bDelta)
	bPrime, _ := Dec(enc, sk, max)
	fmt.Println(bPrime)
	//assert.Equal(t, b, dec)
	assert.Equal(t, b, bPrime)
}
