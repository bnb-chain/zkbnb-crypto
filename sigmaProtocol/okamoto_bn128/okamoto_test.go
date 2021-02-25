package okamoto_bn128

import (
	"ZKSneak/ZKSneak-crypto/ecc/bn128"
	"ZKSneak/ZKSneak-crypto/elgamal/twistedElgamal_bn128"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	_, pk := twistedElgamal_bn128.GenKeyPair()
	b := big.NewInt(4)
	r, _ := rand.Int(rand.Reader, ORDER)
	C := twistedElgamal_bn128.Enc(b, r, pk)
	g, h := bn128.GetG1TwoBaseAffine()
	a, z, A := Prove(r, b, g, h, C.CR)
	res := Verify(a, z, g, h, A, C.CR)
	assert.True(t, res, "should be true")
}
