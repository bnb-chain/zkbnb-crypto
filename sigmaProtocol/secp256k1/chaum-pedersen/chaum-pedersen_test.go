package chaum_pedersen

import (
	"Zecrey-crypto/ecc/zp256"
	"Zecrey-crypto/elgamal/secp256k1/twistedElgamal"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestProveVerify(t *testing.T) {
	g := zp256.Base()
	sk, pk := twistedElgamal.GenKeyPair()
	r1 := zp256.RandomValue()
	r2 := zp256.RandomValue()
	b := big.NewInt(3)
	CPrime := twistedElgamal.Enc(b, r1, pk)
	CTilde := twistedElgamal.Enc(b, r2, pk)
	u := zp256.Add(CPrime.CR, zp256.Neg(CTilde.CR))
	v := pk
	w := zp256.ScalarMult(u, sk)
	w2 := zp256.Add(CPrime.CL, zp256.Neg(CTilde.CL))
	fmt.Println("w2 == w:", zp256.Equal(w2, w))
	z, Vt, Wt := Prove(sk, g, u, v, w2)
	res := Verify(z, g, u, Vt, Wt, v, w)
	assert.True(t, res, "should be true")
}
