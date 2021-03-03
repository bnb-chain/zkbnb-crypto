package chaum_pedersen_bn128

import (
	"ZKSneak-crypto/ecc/bn128"
	"ZKSneak-crypto/ffmath"
	"crypto/rand"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

// prove v = g^{\beta} \and w = u^{\beta}
func Prove(beta *big.Int, g, u, v, w *bn256.G1Affine) (z *big.Int, Vt, Wt *bn256.G1Affine) {
	// betat \gets_R Z_p
	betat, _ := rand.Int(rand.Reader, ORDER)
	// Vt = g^{betat}
	Vt = new(bn256.G1Affine).ScalarMultiplication(g, betat)
	// Wt = u^{betat}
	Wt = new(bn256.G1Affine).ScalarMultiplication(u, betat)
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// z = betat + beta * c
	z = ffmath.AddMod(betat, ffmath.MultiplyMod(c, beta, ORDER), ORDER)
	return z, Vt, Wt
}

func Verify(z *big.Int, g, u, Vt, Wt, v, w *bn256.G1Affine) bool {
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// check if g^z = Vt * v^c
	l1 := new(bn256.G1Affine).ScalarMultiplication(g, z)
	r1 := bn128.G1AffineMul(Vt, new(bn256.G1Affine).ScalarMultiplication(v, c))
	// check if u^z = Wt * w^c
	l2 := new(bn256.G1Affine).ScalarMultiplication(u, z)
	r2 := bn128.G1AffineMul(Wt, new(bn256.G1Affine).ScalarMultiplication(w, c))
	return l1.Equal(r1) && l2.Equal(r2)
}
