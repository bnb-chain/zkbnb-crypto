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

package zecrey

import (
	"errors"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"math/big"
)

/*
	ElgamalEnc: generate ElGamalEnc for the value b
	@pkStr: string of pk
	@b: enc amount
*/
//func ElgamalEnc(pkStr string, b int64) (CStr string, err error) {
//	// parse pk
//	pk, err := curve.FromString(pkStr)
//	if err != nil {
//		return "", err
//	}
//	// r \gets_R \mathbb{Z}_p
//	r := curve.RandomValue()
//	// call elgamal enc
//	C, err := twistedElgamal.Enc(big.NewInt(b), r, pk)
//	if err != nil {
//		return "", err
//	}
//	return C.String(), nil
//}

/*
	ElgamalDec: dec function for ElGamalEnc
	@CStr: string of encryption value(ElGamalEnc)
	@skStr: string of Sk
	@start: start value
	@end: max value of dec
*/
//func ElgamalDec(CStr string, skStr string, start, end int64) (res int64, err error) {
//	if start < 0 || end < 0 || start > end {
//		return 0, errors.New("[ElgamalDec] invalid start or end")
//	}
//	// parse C
//	C, err := twistedElgamal.FromString(CStr)
//	if err != nil {
//		return 0, err
//	}
//	// parse Sk
//	sk, b := new(big.Int).SetString(skStr, 10)
//	if !b {
//		return 0, errors.New("[ElgamalDec] invalid encryption string")
//	}
//	// if CL is zero point, just dec CR
//	if C.CL.Equal(curve.ZeroPoint()) {
//		base := curve.H
//		current := curve.ZeroPoint()
//		for i := start; i < end; i++ {
//			if current.Equal(C.CR) {
//				return i, nil
//			}
//			if curve.Neg(current).Equal(C.CR) {
//				return -i, nil
//			}
//			current.Add(current, base)
//		}
//		return 0, errors.New("[ElgamalDec] unable to decrypt")
//	}
//	// call elgamal dec
//	decVal, err := twistedElgamal.DecByStart(C, sk, int64(start), int64(end))
//	if err != nil {
//		return 0, err
//	}
//	return decVal.Int64(), nil
//}

/*
	ElgamalRawDec: raw dec function for ElGamalEnc
	@CStr: string of encryption value(ElGamalEnc)
	@skStr: string of Sk
*/
func ElgamalRawDec(CStr string, skStr string) (res string, err error) {
	// parse C
	C, err := twistedElgamal.FromString(CStr)
	if err != nil {
		return "", err
	}
	// if CL is zero point, just return CR
	if C.CL.Equal(curve.ZeroPoint()) {
		return curve.ToString(C.CR), nil
	}
	// parse Sk
	sk, b := new(big.Int).SetString(skStr, 10)
	if !b {
		return "", errors.New("[ElgamalRawDec] invalid private key")
	}
	// call elgamal dec
	// (pk^r)^{Sk^{-1}}
	skInv := ffmath.ModInverse(sk, curve.Order)
	gExpr := curve.ScalarMul(C.CL, skInv)
	hExpb := curve.Add(C.CR, curve.Neg(gExpr))
	return curve.ToString(hExpb), nil
}
