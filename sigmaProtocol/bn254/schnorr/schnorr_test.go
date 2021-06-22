package schnorr

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/elgamal/bn254/twistedElgamal"
	"gotest.tools/assert"
	"testing"
)

// pk = g^{sk}
func TestProveVerify(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	base := zbn254.G1BaseAffine()
	z, A := Prove(sk, base, pk)
	res := Verify(z, A, pk, base)
	assert.Equal(t, true, res)
}
