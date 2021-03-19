package schnorr

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

// want to prove R = base^x
func Prove(x *fr.Element, base *bn256.G1Affine, R *bn256.G1Affine) (z *fr.Element, A *bn256.G1Affine) {
	// r
	r, _ := new(fr.Element).SetRandom()
	// A = base^r
	A = zbn256.G1ScalarMult(base, r)
	// c = H(A,r)
	c := HashSchnorr(A, R)
	// z = r + c*x
	z = ffmath.Add(r, ffmath.Multiply(c, x))
	return z, A
}

// check base^z = A * r^c
func Verify(z *fr.Element, A *bn256.G1Affine, R *bn256.G1Affine, base *bn256.G1Affine) bool {
	// cal c = H(A,r)
	c := HashSchnorr(A, R)
	l := zbn256.G1ScalarMult(base, z)
	r := zbn256.G1AffineMul(A, zbn256.G1ScalarMult(R, c))
	return l.Equal(r)
}
