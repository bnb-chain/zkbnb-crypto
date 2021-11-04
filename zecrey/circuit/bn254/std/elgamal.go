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

package std

import "github.com/consensys/gnark/std/algebra/twistededwards"

/*
	ElGamalEncConstraints describes ElGamal Enc in circuit
*/
type ElGamalEncConstraints struct {
	CL Point // Pk^r
	CR Point // g^r Waste^b
}

func NegElgamal(api API, C ElGamalEncConstraints) ElGamalEncConstraints {
	return ElGamalEncConstraints{
		CL: *C.CL.Neg(api, &C.CL),
		CR: *C.CR.Neg(api, &C.CR),
	}
}

func Enc(api API, h Point, b Variable, r Variable, pk Point, params twistededwards.EdCurve) ElGamalEncConstraints {
	var CL, gr, CR Point
	CL.ScalarMulNonFixedBase(api, &pk, r, params)
	gr.ScalarMulFixedBase(api, params.BaseX, params.BaseY, r, params)
	CR.ScalarMulNonFixedBase(api, &h, b, params)
	CR.AddGeneric(api, &CR, &gr, params)
	return ElGamalEncConstraints{CL: CL, CR: CR}
}

func EncAdd(api API, C, CDelta ElGamalEncConstraints, params twistededwards.EdCurve) ElGamalEncConstraints {
	C.CL.AddGeneric(api, &C.CL, &CDelta.CL, params)
	C.CR.AddGeneric(api, &C.CR, &CDelta.CR, params)
	return C
}

func EncSub(api API, C, CDelta ElGamalEncConstraints, params twistededwards.EdCurve) ElGamalEncConstraints {
	var CL, CR Point
	CL.AddGeneric(api, &C.CL, CDelta.CL.Neg(api, &CDelta.CL), params)
	CR.AddGeneric(api, &C.CR, CDelta.CR.Neg(api, &CDelta.CR), params)
	return ElGamalEncConstraints{CL: CL, CR: CR}
}

func ZeroElgamal(api API) ElGamalEncConstraints {
	return ElGamalEncConstraints{CL: zeroPoint(api), CR: zeroPoint(api)}
}

func SelectElgamal(api API, flag Variable, a, b ElGamalEncConstraints) ElGamalEncConstraints {
	CLX := api.Select(flag, a.CL.X, b.CL.X)
	CLY := api.Select(flag, a.CL.Y, b.CL.Y)
	CRX := api.Select(flag, a.CR.X, b.CR.X)
	CRY := api.Select(flag, a.CR.Y, b.CR.Y)
	return ElGamalEncConstraints{CL: Point{X: CLX, Y: CLY}, CR: Point{X: CRX, Y: CRY}}
}

func printEnc(api API, a ElGamalEncConstraints) {
	api.Println(a.CL.X)
	api.Println(a.CL.Y)
	api.Println(a.CR.X)
	api.Println(a.CR.Y)
}
