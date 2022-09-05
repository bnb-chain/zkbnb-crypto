package src

import (
	"math/big"

	"syscall/js"

	"github.com/bnb-chain/zkbnb-crypto/util"
)

func CleanPackedAmountUtil() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "invalid clean packed amount param"
		}
		amount := args[0].String()
		a, isValid := new(big.Int).SetString(amount, 10)
		if !isValid {
			return "input should be big int"
		}
		res, err := util.CleanPackedAmount(a)
		if err != nil {
			return err.Error()
		}
		return res.String()
	})
	return helperFunc
}

func CleanPackedFeeUtil() js.Func {
	helperFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "invalid clean packed fee param"
		}
		amount := args[0].String()
		a, isValid := new(big.Int).SetString(amount, 10)
		if !isValid {
			return "input should be big int"
		}
		res, err := util.CleanPackedFee(a)
		if err != nil {
			return err.Error()
		}
		return res.String()
	})
	return helperFunc
}
