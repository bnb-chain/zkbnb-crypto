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

func EncAdd(cs *ConstraintSystem, C, CDelta ElGamalEncConstraints, params twistededwards.EdCurve) ElGamalEncConstraints {
	C.CL.AddGeneric(cs, &C.CL, &CDelta.CL, params)
	C.CR.AddGeneric(cs, &C.CR, &CDelta.CR, params)
	return C
}
