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
	"github.com/zecrey-labs/zecrey-crypto/ecc/zp256"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
)

type P256 = zp256.P256

// prove \alpha,\beta st. U = g^{\alpha} h^{\beta}
func Prove(alpha, beta *big.Int, g, h *P256, U *P256) (a, z *big.Int, A *P256) {
	// at,bt \gets_R Z_p
	at := zp256.RandomValue()
	bt := zp256.RandomValue()
	// A = g^a h^b
	A = zp256.Add(zp256.ScalarBaseMul(at), zp256.ScalarHBaseMul(bt))
	// c = H(A,U)
	c := HashOkamoto(A, U)
	// a = at + c * alpha, z = bt + c * beta
	a = ffmath.Add(at, ffmath.Multiply(c, alpha))
	z = ffmath.Add(bt, ffmath.Multiply(c, beta))
	return a, z, A
}

func Verify(a, z *big.Int, g, h, A, U *P256) bool {
	// cal c = H(A,U)
	c := HashOkamoto(A, U)
	// check if g^a h^z = A * U^c
	l := zp256.Add(zp256.ScalarBaseMul(a), zp256.ScalarHBaseMul(z))
	r := zp256.Add(A, zp256.ScalarMul(U, c))
	return zp256.Equal(l, r)
}
