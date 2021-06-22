package wasm

import (
	"math/big"
	"syscall/js"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
)

/*
	ElgamalEnc: generate ElGamalEnc for the value b
	@pkStr: string of pk
	@b: enc amount
*/
func ElgamalEnc() js.Func {
	elgamalEncFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 2 {
			return 10002
		}
		// read pk
		pkStr := args[0].String()
		// read b
		b := args[1].Int()
		// parse pk
		pk, err := curve.FromString(pkStr)
		if err != nil {
			return 10003
		}
		// r \gets_R \mathbb{Z}_p
		r := curve.RandomValue()
		// call elgamal enc
		C, err := twistedElgamal.Enc(big.NewInt(int64(b)), r, pk)
		if err != nil {
			return 10004
		}
		return C.String()
	})
	return elgamalEncFunc
}

/*
	ElgamalDec: dec function for ElGamalEnc
	@CStr: string of encryption value(ElGamalEnc)
	@skStr: string of sk
	@start: start value
	@end: max value of dec
*/
func ElgamalDec() js.Func {
	elgamalDecFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 4 {
			return 10001
		}
		// read values
		CStr := args[0].String()
		skStr := args[1].String()
		start := args[2].Int()
		end := args[3].Int()
		if start < 0 || end < 0 || start < end {
			return 10006
		}
		// parse C
		C, err := twistedElgamal.FromString(CStr)
		if err != nil {
			return 10002
		}
		// parse sk
		sk, b := new(big.Int).SetString(skStr, 10)
		if !b {
			return 10003
		}
		// call elgamal dec
		decVal, err := twistedElgamal.DecByStart(C, sk, int64(start), int64(end))
		if err != nil {
			return 10004
		}
		return decVal.Int64()
	})
	return elgamalDecFunc
}
