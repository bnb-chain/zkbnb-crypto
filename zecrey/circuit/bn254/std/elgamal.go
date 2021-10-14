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

func negElgamal(cs *ConstraintSystem, C ElGamalEncConstraints) ElGamalEncConstraints {
	return ElGamalEncConstraints{
		CL: *C.CL.Neg(cs, &C.CL),
		CR: *C.CR.Neg(cs, &C.CR),
	}
}

func encAdd(cs *ConstraintSystem, C, CDelta ElGamalEncConstraints, params twistededwards.EdCurve) ElGamalEncConstraints {
	C.CL.AddGeneric(cs, &C.CL, &CDelta.CL, params)
	C.CR.AddGeneric(cs, &C.CR, &CDelta.CR, params)
	return C
}

func encSub(cs *ConstraintSystem, C, CDelta ElGamalEncConstraints, params twistededwards.EdCurve) ElGamalEncConstraints {
	C.CL.AddGeneric(cs, &C.CL, CDelta.CL.Neg(cs, &CDelta.CL), params)
	C.CL.AddGeneric(cs, &C.CR, CDelta.CR.Neg(cs, &CDelta.CR), params)
	return C
}
