package okamoto

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestProveVerify(t *testing.T) {
	_, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(4)
	r := curve.RandomValue()
	C, _ := twistedElgamal.Enc(b, r, pk)
	g := curve.G
	h := H
	a, z, A := Prove(r, b, g, h, C.CR)
	res := Verify(a, z, g, h, A, C.CR)
	assert.True(t, res, "should be true")
}
