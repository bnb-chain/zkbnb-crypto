package schnorr

import (
	"Zecrey-crypto/ecc/zbn256"
	"Zecrey-crypto/elgamal/bn256/twistedElgamal"
	"gotest.tools/assert"
	"testing"
)

// pk = g^{sk}
func TestProveVerify(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	base := zbn256.G1BaseAffine()
	z, A := Prove(sk, base, pk)
	res := Verify(z, A, pk, base)
	assert.Equal(t, true, res)
}
