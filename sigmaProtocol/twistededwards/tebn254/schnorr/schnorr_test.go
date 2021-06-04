package schnorr

import (
	"gotest.tools/assert"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

// pk = g^{sk}
func TestProveVerify(t *testing.T) {
	sk, pk := twistedElgamal.GenKeyPair()
	g := curve.G
	z, A := Prove(sk, g, pk)
	res := Verify(z, A, pk, g)
	assert.Equal(t, true, res)
}
