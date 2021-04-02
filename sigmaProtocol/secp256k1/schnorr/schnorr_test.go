package schnorr

import (
	"PrivaL-crypto/ecc/zp256"
	"PrivaL-crypto/elgamal/secp256k1/twistedElgamal"
	"gotest.tools/assert"
	"testing"
)

// pk = g^{sk}
func TestProveVerify(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	g := zp256.Base()
	z, A := Prove(sk, g, pk)
	res := Verify(z, A, pk, g)
	assert.Equal(t, true, res)
}
