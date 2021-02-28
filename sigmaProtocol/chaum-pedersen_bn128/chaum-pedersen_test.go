package chaum_pedersen_bn128

import (
	"ZKSneak-crypto/ecc/bn128"
	"ZKSneak-crypto/elgamal/twistedElgamal_bn128"
	"crypto/rand"
	"fmt"
	"github.com/consensys/gurvy/bn256"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	g := bn128.GetG1BaseAffine()
	sk, pk := twistedElgamal_bn128.GenKeyPair()
	r1, _ := rand.Int(rand.Reader, ORDER)
	r2, _ := rand.Int(rand.Reader, ORDER)
	b := big.NewInt(3)
	CPrime := twistedElgamal_bn128.Enc(b, r1, pk)
	CTilde := twistedElgamal_bn128.Enc(b, r2, pk)
	u := bn128.G1AffineMul(CPrime.CR, new(bn256.G1Affine).Neg(CTilde.CR))
	v := pk
	w := new(bn256.G1Affine).ScalarMultiplication(u, sk)
	w2 := bn128.G1AffineMul(CPrime.CL, new(bn256.G1Affine).Neg(CTilde.CL))
	fmt.Println("w2 == w:", w2.Equal(w))
	z, Vt, Wt := Prove(sk, g, u, v, w2)
	res := Verify(z, g, u, Vt, Wt, v, w)
	assert.True(t, res, "should be true")
}
