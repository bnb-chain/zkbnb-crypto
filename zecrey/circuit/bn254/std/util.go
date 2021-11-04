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

func writePointIntoBuf(hFunc *MiMC, p Point) {
	hFunc.Write(p.X, p.Y)
}

func writeEncIntoBuf(hFunc *MiMC, enc ElGamalEncConstraints) {
	writePointIntoBuf(hFunc, enc.CL)
	writePointIntoBuf(hFunc, enc.CR)
}

func zeroPoint(api API) Point {
	return Point{X: api.Constant(0), Y: api.Constant(1)}
}

func Xor(api API, a, b Variable, size int) Variable {
	aBits := api.ToBinary(a, size)
	bBits := api.ToBinary(b, size)
	var resBits []Variable
	for i := 0; i < size; i++ {
		resBits = append(resBits, api.Xor(aBits[i], bBits[i]))
	}
	return api.FromBinary(resBits...)
}

func FixedCurveParam(api API) Variable {
	return api.Constant(FixedCurve)
}
