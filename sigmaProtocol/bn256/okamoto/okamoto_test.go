package okamoto

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/elgamal/bn256/twistedElgamal"
	"github.com/consensys/gurvy/bn256/fr"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProveVerify(t *testing.T) {
	_, pk := twistedElgamal.GenKeyPair()
	b := new(fr.Element).SetUint64(4)
	r, _ := new(fr.Element).SetRandom()
	C := twistedElgamal.Enc(b, r, pk)
	g, h := zbn256.GetG1TwoBaseAffine()
	a, z, A := Prove(r, b, g, h, C.CR)
	res := Verify(a, z, g, h, A, C.CR)
	assert.True(t, res, "should be true")
}
