package chaum_pedersen_bn128

import (
	"ZKSneak/ZKSneak-crypto/ecc/bn128"
	"crypto/rand"
	"github.com/consensys/gurvy/bn256"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProveVerify(t *testing.T) {
	beta, _ := rand.Int(rand.Reader, ORDER)
	g, u := bn128.GetG1TwoBaseAffine()
	v := new(bn256.G1Affine).ScalarMultiplication(g, beta)
	w := new(bn256.G1Affine).ScalarMultiplication(u, beta)
	z, Vt, Wt := Prove(beta, g, u, v, w)
	res := Verify(z, g, u, Vt, Wt, v, w)
	assert.True(t, res, "should be true")
}
