package chaum_pedersen

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/elgamal/bn256/twistedElgamal"
	"fmt"
	"github.com/consensys/gurvy/bn256"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	g := zbn254.G1BaseAffine()
	sk, pk := twistedElgamal.GenKeyPair()
	r1 := zbn254.RandomValue()
	r2 := zbn254.RandomValue()
	b := big.NewInt(3)
	CPrime := twistedElgamal.Enc(b, r1, pk)
	CTilde := twistedElgamal.Enc(b, r2, pk)
	u := zbn254.G1Add(CPrime.CR, new(bn256.G1Affine).Neg(CTilde.CR))
	v := pk
	w := zbn254.G1ScalarMult(u, sk)
	w2 := zbn254.G1Add(CPrime.CL, new(bn256.G1Affine).Neg(CTilde.CL))
	fmt.Println("w2 == w:", w2.Equal(w))
	z, Vt, Wt := Prove(sk, g, u, v, w2)
	res := Verify(z, g, u, Vt, Wt, v, w)
	assert.True(t, res, "should be true")
}
