package chaum_pedersen

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

func TestProveVerify(t *testing.T) {
	g := G
	sk, pk := twistedElgamal.GenKeyPair()
	r1 := curve.RandomValue()
	r2 := curve.RandomValue()
	b := big.NewInt(3)
	CPrime, _ := twistedElgamal.Enc(b, r1, pk)
	CTilde, _ := twistedElgamal.Enc(b, r2, pk)
	u := curve.Add(CPrime.CR, curve.Neg(CTilde.CR))
	v := pk
	w := curve.ScalarMul(u, sk)
	w2 := curve.Add(CPrime.CL, curve.Neg(CTilde.CL))
	fmt.Println("w2 == w:", w2.Equal(w))
	z, Vt, Wt := Prove(sk, g, u, v, w2)
	res := Verify(z, g, u, Vt, Wt, v, w)
	assert.True(t, res, "should be true")
}
