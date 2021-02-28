package schnorr_bn128

import (
	"ZKSneak-crypto/ecc/bn128"
	"ZKSneak-crypto/ffmath"
	"crypto/rand"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

// want to prove r = base^x
func Prove(x *big.Int, base *bn256.G1Affine, R *bn256.G1Affine) (z *big.Int, A *bn256.G1Affine) {
	// r
	r, _ := rand.Int(rand.Reader, ORDER)
	// A = base^r
	A = new(bn256.G1Affine).ScalarMultiplication(base, r)
	// c = H(A,r)
	c := HashSchnorr(A, R)
	// z = r + c*x
	z = ffmath.AddMod(r, ffmath.MultiplyMod(c, x, ORDER), ORDER)
	return z, A
}

// check base^z = A * r^c
func Verify(z *big.Int, A *bn256.G1Affine, R *bn256.G1Affine, base *bn256.G1Affine) bool {
	// cal c = H(A,r)
	c := HashSchnorr(A, R)
	l := new(bn256.G1Affine).ScalarMultiplication(base, z)
	r := bn128.G1AffineMul(A, new(bn256.G1Affine).ScalarMultiplication(R, c))
	return l.Equal(r)
}
