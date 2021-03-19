package linear

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

// u = \prod_{i=1}^n g_{i}^{x_i}
func Prove(xArr []*fr.Element, gArr, uArr []*bn256.G1Affine) (zArr []*fr.Element, UtArr []*bn256.G1Affine) {
	m := len(uArr)
	n := len(xArr)
	var xtArr []*fr.Element
	for i := 0; i < n; i++ {
		xti, _ := new(fr.Element).SetRandom()
		xtArr = append(xtArr, xti)
	}
	for i := 0; i < m; i++ {
		var Uti *bn256.G1Affine
		for j := 0; j < n; j++ {
			if j == 0 {
				Uti = zbn256.G1ScalarMult(gArr[i*n+j], xtArr[j])
				continue
			}
			Uti = zbn256.G1AffineMul(Uti, zbn256.G1ScalarMult(gArr[i*n+j], xtArr[j]))
		}
		UtArr = append(UtArr, Uti)
	}
	// c = HashLinear
	c := HashLinear(UtArr, uArr)
	for i := 0; i < n; i++ {
		zi := ffmath.Add(xtArr[i], ffmath.Multiply(c, xArr[i]))
		zArr = append(zArr, zi)
	}
	return zArr, UtArr
}

func Verify(zArr []*fr.Element, gArr, uArr, UtArr []*bn256.G1Affine) bool {
	n := len(zArr)
	m := len(uArr)
	// cal c
	c := HashLinear(UtArr, uArr)
	for i := 0; i < m; i++ {
		var l, r *bn256.G1Affine
		for j := 0; j < n; j++ {
			if j == 0 {
				l = zbn256.G1ScalarMult(gArr[i*n+j], zArr[j])
				continue
			}
			l = zbn256.G1AffineMul(l, zbn256.G1ScalarMult(gArr[i*n+j], zArr[j]))
		}
		r = zbn256.G1AffineMul(UtArr[i], zbn256.G1ScalarMult(uArr[i], c))
		if !l.Equal(r) {
			return false
		}
	}
	return true
}
