package okamoto

import (
	"PrivaL-crypto/ecc/zp256"
	"PrivaL-crypto/elgamal/secp256k1/twistedElgamal"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	_, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(4)
	r := zp256.RandomValue()
	C := twistedElgamal.Enc(b, r, pk)
	g := zp256.Base()
	h := zp256.H
	a, z, A := Prove(r, b, g, h, C.CR)
	res := Verify(a, z, g, h, A, C.CR)
	assert.True(t, res, "should be true")
}
