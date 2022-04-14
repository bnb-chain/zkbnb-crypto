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

package pedersen

import (
	"math/big"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
)

type Point = curve.Point

/**
compute commitment of a: C = g^a h^r
@a: the value needs to be committed
@r: the random value
@g: group generator
@h: another group generator
*/
func Commit(a *big.Int, r *big.Int, g, h *Point) (*Point, error) {
	if a == nil || r == nil || g == nil || h == nil ||
		curve.IsZero(g) || curve.IsZero(h) {
		return nil, ErrParams
	}
	commitment := curve.ScalarMul(g, a)
	commitment.Add(commitment, curve.ScalarMul(h, r))
	return commitment, nil
}

/**
Open a commitment: C' = g^a h^r
@C: commitment
@a: the value that is already committed
@r: the random value that used to commit
@g: group generator
@h: another group generator
*/
func Open(C *Point, a, r *big.Int, g, h *Point) (bool, error) {
	if C == nil || a == nil || r == nil ||
		g == nil || h == nil ||
		!g.IsOnCurve() || !h.IsOnCurve() || curve.IsZero(g) || curve.IsZero(h) {
		return false, ErrParams
	}
	commitment := curve.ScalarMul(g, a)
	commitment.Add(commitment, curve.ScalarMul(h, r))
	if C.Equal(commitment) {
		return true, nil
	}
	return false, nil
}
