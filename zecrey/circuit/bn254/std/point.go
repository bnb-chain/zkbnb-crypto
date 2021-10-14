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

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/twistededwards"
)

type NegConstraints struct {
	G    Point
	P, N Point
}

func (circuit *NegConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	PNeg := Neg(cs, circuit.P, params)
	PNeg.X = cs.Sub(PNeg.X, circuit.N.X)
	cs.AssertIsEqual(PNeg.X, circuit.N.X)
	cs.AssertIsEqual(PNeg.Y, circuit.N.Y)
	return nil
}

func Neg(cs *ConstraintSystem, p Point, params twistededwards.EdCurve) *Point {
	res := &Point{
		cs.Constant(0),
		cs.Constant(1),
	}
	// f_r
	r := cs.Constant("21888242871839275222246405745257275088548364400416034343698204186575808495617")
	xNeg := cs.Sub(r, p.X)
	res.X = xNeg
	res.Y = p.Y
	return res
}
