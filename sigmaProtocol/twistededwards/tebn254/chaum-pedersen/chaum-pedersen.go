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

package chaum_pedersen

import (
	"math/big"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/ffmath"
)

type Point = curve.Point

var (
	G     = curve.G
)

// prove v = g^{\beta} \and w = u^{\beta}
func Prove(beta *big.Int, g, u, v, w *Point) (z *big.Int, Vt, Wt *Point) {
	// betat \gets_R Z_p
	betat := curve.RandomValue()
	// Vt = g^{betat}
	Vt = curve.ScalarMul(g, betat)
	// Wt = u^{betat}
	Wt = curve.ScalarMul(u, betat)
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// z = betat + beta * c
	z = ffmath.Add(betat, ffmath.Multiply(c, beta))
	return z, Vt, Wt
}

func Verify(z *big.Int, g, u, Vt, Wt, v, w *Point) bool {
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// check if g^z = Vt * v^c
	l1 := curve.ScalarMul(g, z)
	r1 := curve.Add(Vt, curve.ScalarMul(v, c))
	// check if u^z = Wt * w^c
	l2 := curve.ScalarMul(u, z)
	r2 := curve.Add(Wt, curve.ScalarMul(w, c))
	return l1.Equal(r1) && l2.Equal(r2)
}
