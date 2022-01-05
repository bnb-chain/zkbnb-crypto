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

package schnorr

import (
	"fmt"
	"math/big"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
)

type Point = curve.Point

var Order = curve.Order

// want to prove R = base^x
func Prove(x *big.Int, base *Point, R *Point) (z *big.Int, A *Point) {
	// r
	r := curve.RandomValue()
	// A = base^r
	A = curve.ScalarMul(base, r)
	// c = H(A,r)
	c := HashSchnorr(A, R)
	// z = r + c*x
	z = ffmath.AddMod(r, ffmath.Multiply(c, x), Order)
	return z, A
}

// check base^z = A * r^c
func Verify(z *big.Int, A *Point, R *Point, base *Point) bool {
	// cal c = H(A,r)
	c := HashSchnorr(A, R)
	l := curve.ScalarMul(base, z)
	fmt.Println("l.x:", l.X.String())
	fmt.Println("l.y:", l.Y.String())
	r := curve.Add(A, curve.ScalarMul(R, c))
	return l.Equal(r)
}
