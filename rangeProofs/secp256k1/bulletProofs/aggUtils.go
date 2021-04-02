package bulletProofs

import (
	"PrivaL-crypto/ffmath"
	"math/big"
)

func DecomposeVec(xs []*big.Int, u int64, l int64) ([]int64, error) {
	var result []int64
	for i := 0; i < len(xs); i++ {
		vec, err := Decompose(xs[i], u, l)
		if err != nil {
			return nil, err
		}
		result = append(result, vec...)
	}
	return result, nil
}

/*
delta(y,z) = (z-z^2) . < 1^n, y^n > - \sum_{j=1}^m z^{j+2} . < 1^n, 2^n >
*/
func aggDelta(y, z *big.Int, N int64, m int64) *big.Int {
	var (
		result *big.Int
	)
	nm := N * m
	// < 1^{nm}, y^{nm} >
	v1m, _ := VectorCopy(big.NewInt(1), nm)
	vy := powerOfVec(y, nm)
	sp1y, _ := ScalarVecMul(v1m, vy)

	// < 1^n, 2^n >
	v1n, _ := VectorCopy(big.NewInt(1), N)
	p2n := powerOfVec(big.NewInt(2), N)
	sp12, _ := ScalarVecMul(v1n, p2n)

	// delta(y,z) = (z-z^2) . < 1^{nm}, y^{nm} > - \sum_{j=1}^m z^{j+2} . < 1^n, 2^n >
	z2 := ffmath.MultiplyMod(z, z, Order)
	tz := new(big.Int).Set(z2)
	result = ffmath.SubMod(z, z2, Order)
	result = ffmath.MultiplyMod(result, sp1y, Order)
	for j := int64(1); j <= m; j++ {
		tz = ffmath.MultiplyMod(tz, z, Order)
		result = ffmath.SubMod(result, ffmath.MultiplyMod(tz, sp12, Order), Order)
	}

	return result
}
