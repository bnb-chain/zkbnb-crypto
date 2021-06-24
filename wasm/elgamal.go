/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
			return ErrInvalidEncParams
		}
		// read pk
		pkStr := args[0].String()
		// read b
		b := args[1].Int()
		// parse pk
		pk, err := curve.FromString(pkStr)
		if err != nil {
			return ErrParsePoint
		}
		// r \gets_R \mathbb{Z}_p
		r := curve.RandomValue()
		// call elgamal enc
		C, err := twistedElgamal.Enc(big.NewInt(int64(b)), r, pk)
		if err != nil {
			return ErrElGamalEnc
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
			return ErrInvalidDecParams
		}
		// read values
		CStr := args[0].String()
		skStr := args[1].String()
		start := args[2].Int()
		end := args[3].Int()
		if start < 0 || end < 0 || start > end {
			return ErrInvalidDecParams
		}
		// parse C
		C, err := twistedElgamal.FromString(CStr)
		if err != nil {
			return ErrParseEnc
		}
		// parse sk
		sk, b := new(big.Int).SetString(skStr, 10)
		if !b {
			return ErrParseBigInt
		}
		// call elgamal dec
		decVal, err := twistedElgamal.DecByStart(C, sk, int64(start), int64(end))
		if err != nil {
			return ErrElGamalDec
		}
		return decVal.Int64()
	})
	return elgamalDecFunc
}
