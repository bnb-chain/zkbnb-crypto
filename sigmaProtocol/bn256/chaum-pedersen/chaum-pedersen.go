package chaum_pedersen

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

// prove v = g^{\beta} \and w = u^{\beta}
func Prove(beta *fr.Element, g, u, v, w *bn256.G1Affine) (z *fr.Element, Vt, Wt *bn256.G1Affine) {
	// betat \gets_R Z_p
	betat, _ := new(fr.Element).SetRandom()
	// Vt = g^{betat}
	Vt = zbn256.G1ScalarMult(g, betat)
	// Wt = u^{betat}
	Wt = zbn256.G1ScalarMult(u, betat)
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// z = betat + beta * c
	z = ffmath.Add(betat, ffmath.Multiply(c, beta))
	return z, Vt, Wt
}

func Verify(z *fr.Element, g, u, Vt, Wt, v, w *bn256.G1Affine) bool {
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// check if g^z = Vt * v^c
	l1 := zbn256.G1ScalarMult(g, z)
	r1 := zbn256.G1AffineMul(Vt, zbn256.G1ScalarMult(v, c))
	// check if u^z = Wt * w^c
	l2 := zbn256.G1ScalarMult(u, z)
	r2 := zbn256.G1AffineMul(Wt, zbn256.G1ScalarMult(w, c))
	return l1.Equal(r1) && l2.Equal(r2)
}
