package okamoto

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

// prove \alpha,\beta st. U = g^{\alpha} h^{\beta}
func Prove(alpha, beta *fr.Element, g, h *bn256.G1Affine, U *bn256.G1Affine) (a, z *fr.Element, A *bn256.G1Affine) {
	// at,bt \gets_R Z_p
	at, _ := new(fr.Element).SetRandom()
	bt, _ := new(fr.Element).SetRandom()
	// A = g^a h^b
	A = zbn256.G1AffineMul(zbn256.G1ScalarBaseMult(at), zbn256.G1ScalarHBaseMult(bt))
	// c = H(A,U)
	c := HashOkamoto(A, U)
	// a = at + c * alpha, z = bt + c * beta
	a = ffmath.Add(at, ffmath.Multiply(c, alpha))
	z = ffmath.Add(bt, ffmath.Multiply(c, beta))
	return a, z, A
}

func Verify(a, z *fr.Element, g, h, A, U *bn256.G1Affine) bool {
	// cal c = H(A,U)
	c := HashOkamoto(A, U)
	// check if g^a h^z = A * U^c
	l := zbn256.G1AffineMul(zbn256.G1ScalarBaseMult(a), zbn256.G1ScalarHBaseMult(z))
	r := zbn256.G1AffineMul(A, zbn256.G1ScalarMult(U, c))
	return l.Equal(r)
}
