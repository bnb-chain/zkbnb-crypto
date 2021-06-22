package chaum_pedersen

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/ffmath"
	"github.com/consensys/gnark-crypto/bn254"
	"math/big"
)

// prove v = g^{\beta} \and w = u^{\beta}
func Prove(beta *big.Int, g, u, v, w *bn254.G1Affine) (z *big.Int, Vt, Wt *bn254.G1Affine) {
	// betat \gets_R Z_p
	betat := zbn254.RandomValue()
	// Vt = g^{betat}
	Vt = zbn254.G1ScalarMul(g, betat)
	// Wt = u^{betat}
	Wt = zbn254.G1ScalarMul(u, betat)
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// z = betat + beta * c
	z = ffmath.AddMod(betat, ffmath.MultiplyMod(c, beta, Order), Order)
	return z, Vt, Wt
}

func Verify(z *big.Int, g, u, Vt, Wt, v, w *bn254.G1Affine) bool {
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// check if g^z = Vt * v^c
	l1 := zbn254.G1ScalarMul(g, z)
	r1 := zbn254.G1Add(Vt, zbn254.G1ScalarMul(v, c))
	// check if u^z = Wt * w^c
	l2 := zbn254.G1ScalarMul(u, z)
	r2 := zbn254.G1Add(Wt, zbn254.G1ScalarMul(w, c))
	return l1.Equal(r1) && l2.Equal(r2)
}
