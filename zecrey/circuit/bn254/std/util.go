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

func zeroPoint(cs *ConstraintSystem) Point {
	return Point{X: cs.Constant(0), Y: cs.Constant(1)}
}

func Xor(cs *ConstraintSystem, a, b Variable, size int) Variable {
	aBits := cs.ToBinary(a, size)
	bBits := cs.ToBinary(b, size)
	var resBits []Variable
	for i := 0; i < size; i++ {
		resBits = append(resBits, cs.Xor(aBits[i], bBits[i]))
	}
	return cs.FromBinary(resBits...)
}

func FixedCurveParam(cs *ConstraintSystem) Variable {
	return cs.Constant(FixedCurve)
}
