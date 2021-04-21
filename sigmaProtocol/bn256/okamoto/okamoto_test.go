package okamoto

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/elgamal/bn256/twistedElgamal"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	_, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(4)
	r := zbn254.RandomValue()
	C := twistedElgamal.Enc(b, r, pk)
	g, h := zbn254.GetG1TwoBaseAffine()
	a, z, A := Prove(r, b, g, h, C.CR)
	res := Verify(a, z, g, h, A, C.CR)
	assert.True(t, res, "should be true")
}
