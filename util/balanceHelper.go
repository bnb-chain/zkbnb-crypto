package util

import (
	"errors"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"log"
	"math/big"
)

var (
	// 2^35 - 1
	PackedAmountMaxMantissa = big.NewInt(34359738367)
	// 2^11 - 1
	PackedFeeMaxMantissa  = big.NewInt(2047)
	PackedAmountMaxAmount = ffmath.Multiply(big.NewInt(34359738367), new(big.Int).Exp(big.NewInt(10), big.NewInt(31), nil))
	PackedFeeMaxAmount    = ffmath.Multiply(big.NewInt(2047), new(big.Int).Exp(big.NewInt(10), big.NewInt(31), nil))
	ZeroBigInt            = big.NewInt(0)
)

func CleanPackedAmount(amount *big.Int) (nAmount *big.Int, err error) {
	if amount.Cmp(ZeroBigInt) < 0 || amount.Cmp(PackedAmountMaxAmount) > 0 {
		log.Println("[ToPackedAmount] invalid amount")
		return nil, errors.New("[ToPackedAmount] invalid amount")
	}
	oAmount := new(big.Int).Set(amount)
	exponent := int64(0)
	for oAmount.Cmp(PackedAmountMaxMantissa) > 0 {
		oAmount = ffmath.Div(oAmount, big.NewInt(10))
		exponent++
	}
	nAmount = ffmath.Multiply(oAmount, new(big.Int).Exp(big.NewInt(10), big.NewInt(exponent), nil))
	return nAmount, nil
}

func CleanPackedFee(amount *big.Int) (nAmount *big.Int, err error) {
	if amount.Cmp(ZeroBigInt) < 0 || amount.Cmp(PackedFeeMaxAmount) > 0 {
		log.Println("[ToPackedFee] invalid amount")
		return nil, errors.New("[ToPackedFee] invalid amount")
	}
	oAmount := new(big.Int).Set(amount)
	exponent := int64(0)
	for oAmount.Cmp(PackedFeeMaxMantissa) > 0 {
		oAmount = ffmath.Div(oAmount, big.NewInt(10))
		exponent++
	}
	nAmount = ffmath.Multiply(oAmount, new(big.Int).Exp(big.NewInt(10), big.NewInt(exponent), nil))
	return nAmount, nil
}
