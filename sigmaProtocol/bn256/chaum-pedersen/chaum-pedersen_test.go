package chaum_pedersen

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/elgamal/bn256/twistedElgamal"
	"fmt"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProveVerify(t *testing.T) {
	g := zbn256.GetG1BaseAffine()
	sk, pk := twistedElgamal.GenKeyPair()
	r1, _ := new(fr.Element).SetRandom()
	r2, _ := new(fr.Element).SetRandom()
	b := new(fr.Element).SetUint64(3)
	CPrime := twistedElgamal.Enc(b, r1, pk)
	CTilde := twistedElgamal.Enc(b, r2, pk)
	u := zbn256.G1AffineMul(CPrime.CR, new(bn256.G1Affine).Neg(CTilde.CR))
	v := pk
	w := zbn256.G1ScalarMult(u, sk)
	w2 := zbn256.G1AffineMul(CPrime.CL, new(bn256.G1Affine).Neg(CTilde.CL))
	fmt.Println("w2 == w:", w2.Equal(w))
	z, Vt, Wt := Prove(sk, g, u, v, w2)
	res := Verify(z, g, u, Vt, Wt, v, w)
	assert.True(t, res, "should be true")
}
