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

package transactions

import "zecrey-crypto/zecrey/circuit/bn254/std"

func selectPk(cs *ConstraintSystem, isFirst Variable, proof std.SwapProofConstraints) (Point, Point) {
	pk := selectPoint(cs, isFirst, proof.ProofPart1.Pk, proof.ProofPart2.Pk)
	receiverPk := selectPoint(cs, isFirst, proof.ProofPart1.ReceiverPk, proof.ProofPart2.ReceiverPk)
	return pk, receiverPk
}

func selectCStar(cs *ConstraintSystem, isFirst Variable, proof std.SwapProofConstraints) (ElGamalEncConstraints, ElGamalEncConstraints) {
	CStar := selectElGamalEnc(cs, isFirst, proof.ProofPart1.CStar, proof.ProofPart2.CStar)
	receiverCStar := selectElGamalEnc(cs, isFirst, proof.ProofPart1.ReceiverCStar, proof.ProofPart2.ReceiverCStar)
	return CStar, receiverCStar
}

func selectElGamalEnc(cs *ConstraintSystem, isFirst Variable, C1, C2 ElGamalEncConstraints) ElGamalEncConstraints {
	CL := selectPoint(cs, isFirst, C1.CL, C2.CL)
	CR := selectPoint(cs, isFirst, C1.CR, C2.CR)
	return ElGamalEncConstraints{CL: CL, CR: CR}
}

func selectPoint(cs *ConstraintSystem, isFirst Variable, p1, p2 Point) Point {
	x := cs.Select(isFirst, p1.X, p2.X)
	y := cs.Select(isFirst, p1.Y, p2.Y)
	return Point{X: x, Y: y}
}
