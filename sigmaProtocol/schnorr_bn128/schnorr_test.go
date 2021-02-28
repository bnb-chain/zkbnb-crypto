package schnorr_bn128

import (
	"ZKSneak-crypto/ecc/bn128"
	"ZKSneak-crypto/elgamal/twistedElgamal_bn128"
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestProveVerify(t *testing.T) {
	sk, pk := twistedElgamal_bn128.GenKeyPair()
	base := bn128.GetG1BaseAffine()
	z, A := Prove(sk, base, pk)
	res := Verify(z, A, pk, base)
	assert.Equal(t, true, res)
}
