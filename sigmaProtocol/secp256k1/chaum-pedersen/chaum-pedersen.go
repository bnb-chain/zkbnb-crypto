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
	"github.com/zecrey-labs/zecrey-crypto/ecc/zp256"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
)

type P256 = zp256.P256

// prove v = g^{\beta} \and w = u^{\beta}
func Prove(beta *big.Int, g, u, v, w *P256) (z *big.Int, Vt, Wt *P256) {
	// betat \gets_R Z_p
	betat := zp256.RandomValue()
	// Vt = g^{betat}
	Vt = zp256.ScalarMul(g, betat)
	// Wt = u^{betat}
	Wt = zp256.ScalarMul(u, betat)
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// z = betat + beta * c
	z = ffmath.Add(betat, ffmath.Multiply(c, beta))
	return z, Vt, Wt
}

func Verify(z *big.Int, g, u, Vt, Wt, v, w *P256) bool {
	// c = H(Vt,Wt,v,w)
	c := HashChaumPedersen(Vt, Wt, v, w)
	// check if g^z = Vt * v^c
	l1 := zp256.ScalarMul(g, z)
	r1 := zp256.Add(Vt, zp256.ScalarMul(v, c))
	// check if u^z = Wt * w^c
	l2 := zp256.ScalarMul(u, z)
	r2 := zp256.Add(Wt, zp256.ScalarMul(w, c))
	return zp256.Equal(l1, r1) && zp256.Equal(l2, r2)
}
