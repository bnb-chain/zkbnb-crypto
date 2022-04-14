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

package commitRange

import "math/big"

type ComRangeProof struct {
	// binary proof
	Cas, Cbs     [RangeMaxBits]*Point
	Fs, Zas, Zbs [RangeMaxBits]*big.Int
	// same commitment proof
	Zb, Zr, Zrprime *big.Int
	A_T, A_Tprime   *Point
	// public statements
	T, Tprime, G, H *Point
	As              [RangeMaxBits]*Point
}
