package zecrey_legend

import (
	"errors"
	"github.com/zecrey-labs/zecrey-crypto/util"
	"math/big"
)

func CleanPackedAmount(amountStr string) (string, error) {
	amount, isValid := new(big.Int).SetString(amountStr, 10)
	if !isValid {
		return "", errors.New("[CleanPackedAmount] input should be big int")
	}
	cleanedAmount, err := util.CleanPackedAmount(amount)
	return cleanedAmount.String(), err
}

func CleanPackedFee(amountStr string) (string, error) {
	amount, isValid := new(big.Int).SetString(amountStr, 10)
	if !isValid {
		return "", errors.New("[CleanPackedFee] input should be big int")
	}
	cleanedAmount, err := util.CleanPackedFee(amount)
	return cleanedAmount.String(), err
}
