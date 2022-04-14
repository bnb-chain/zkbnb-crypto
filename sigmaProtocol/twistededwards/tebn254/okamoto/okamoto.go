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

package okamoto

import (
	"math/big"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
)

type Point = curve.Point

var (
	H = curve.H
)

// prove \alpha,\beta st. U = g^{\alpha} h^{\beta}
func Prove(alpha, beta *big.Int, g, h *Point, U *Point) (a, z *big.Int, A *Point) {
	// at,bt \gets_R Z_p
	at := curve.RandomValue()
	bt := curve.RandomValue()
	// A = g^a h^b
	A = curve.Add(curve.ScalarBaseMul(at), curve.ScalarMul(H, bt))
	// c = H(A,U)
	c := HashOkamoto(A, U)
	// a = at + c * alpha, z = bt + c * beta
	a = ffmath.Add(at, ffmath.Multiply(c, alpha))
	z = ffmath.Add(bt, ffmath.Multiply(c, beta))
	return a, z, A
}

func Verify(a, z *big.Int, g, h, A, U *Point) bool {
	// cal c = H(A,U)
	c := HashOkamoto(A, U)
	// check if g^a h^z = A * U^c
	l := curve.Add(curve.ScalarBaseMul(a), curve.ScalarMul(H, z))
	r := curve.Add(A, curve.ScalarMul(U, c))
	return l.Equal(r)
}
