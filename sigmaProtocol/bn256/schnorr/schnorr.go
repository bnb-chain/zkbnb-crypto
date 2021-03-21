package schnorr

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/ffmath"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

// want to prove R = base^x
func Prove(x *big.Int, base *bn256.G1Affine, R *bn256.G1Affine) (z *big.Int, A *bn256.G1Affine) {
	// r
	r := zbn256.RandomValue()
	// A = base^r
	A = zbn256.G1ScalarMult(base, r)
	// c = H(A,r)
	c := HashSchnorr(A, R)
	// z = r + c*x
	z = ffmath.AddMod(r, ffmath.MultiplyMod(c, x, Order), Order)
	return z, A
}

// check base^z = A * r^c
func Verify(z *big.Int, A *bn256.G1Affine, R *bn256.G1Affine, base *bn256.G1Affine) bool {
	// cal c = H(A,r)
	c := HashSchnorr(A, R)
	l := zbn256.G1ScalarMult(base, z)
	r := zbn256.G1Add(A, zbn256.G1ScalarMult(R, c))
	return l.Equal(r)
}
