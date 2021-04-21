package zecrey

import (
	"math/big"
	"zecrey-crypto/ecc/zp256"
)

var (
	Order = zp256.Curve.N
	Zero  = big.NewInt(0)
	G     = zp256.Base()
	H     = zp256.H
)

const MAX = 4294967296
