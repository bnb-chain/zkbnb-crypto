package schnorr

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/ffmath"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

// want to prove R = base^x
func Prove(x *big.Int, base *bn256.G1Affine, R *bn256.G1Affine) (z *big.Int, A *bn256.G1Affine) {
	// r
	r := zbn254.RandomValue()
	// A = base^r
	A = zbn254.G1ScalarMul(base, r)
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
	l := zbn254.G1ScalarMul(base, z)
	r := zbn254.G1Add(A, zbn254.G1ScalarMul(R, c))
	return l.Equal(r)
}
