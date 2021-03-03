package okamoto_bn128

import (
	"ZKSneak-crypto/ecc/bn128"
	"ZKSneak-crypto/ffmath"
	"crypto/rand"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

// prove \alpha,\beta st. U = g^{\alpha} h^{\beta}
func Prove(alpha, beta *big.Int, g, h *bn256.G1Affine, U *bn256.G1Affine) (a, z *big.Int, A *bn256.G1Affine) {
	// at,bt \gets_R Z_p
	at, _ := rand.Int(rand.Reader, ORDER)
	bt, _ := rand.Int(rand.Reader, ORDER)
	// A = g^a h^b
	A = bn128.G1AffineMul(bn128.G1ScalarBaseMult(at), bn128.G1ScalarHBaseMult(bt))
	// c = H(A,U)
	c := HashOkamoto(A, U)
	// a = at + c * alpha, z = bt + c * beta
	a = ffmath.AddMod(at, ffmath.MultiplyMod(c, alpha, ORDER), ORDER)
	z = ffmath.AddMod(bt, ffmath.MultiplyMod(c, beta, ORDER), ORDER)
	return a, z, A
}

func Verify(a, z *big.Int, g, h, A, U *bn256.G1Affine) bool {
	// cal c = H(A,U)
	c := HashOkamoto(A, U)
	// check if g^a h^z = A * U^c
	l := bn128.G1AffineMul(bn128.G1ScalarBaseMult(a), bn128.G1ScalarHBaseMult(z))
	r := bn128.G1AffineMul(A, new(bn256.G1Affine).ScalarMultiplication(U, c))
	return l.Equal(r)
}
