package zecrey

import (
	"math/big"
	"zecrey-crypto/ecc/zp256"
	"zecrey-crypto/ffmath"
)

func RandomVec(n uint) []*big.Int {
	res := make([]*big.Int, n)
	for i := uint(0); i < n; i++ {
		res[i] = zp256.RandomValue()
	}
	return res
}

func VecSum(as []*big.Int) *big.Int {
	res := big.NewInt(0)
	for _, a := range as {
		res = ffmath.Add(res, a)
	}
	res = ffmath.Mod(res, Order)
	return res
}
