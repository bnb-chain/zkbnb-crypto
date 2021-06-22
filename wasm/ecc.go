package wasm

import (
	"math/big"
	"syscall/js"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

/*
	GetL2PublicKey: help the user generates the public key
*/
func GetL2PublicKey() js.Func {
	getL2PublicKeyFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return ErrL2SkParams
		}
		skStr := args[0].String()
		sk, b := new(big.Int).SetString(skStr, 10)
		if !b {
			return ErrL2SkParams
		}
		// pk = g^{sk}
		pk := curve.ScalarBaseMul(sk)
		return curve.ToString(pk)
	})
	return getL2PublicKeyFunc
}
