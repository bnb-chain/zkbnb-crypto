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
	"math/big"
	"github.com/bnb-chain/zkbas-crypto/ecc/zp256"
	"github.com/bnb-chain/zkbas-crypto/ffmath"
)

type P256 = zp256.P256

// want to prove R = base^x
func Prove(x *big.Int, base *P256, R *P256) (z *big.Int, A *P256) {
	// r
	r := zp256.RandomValue()
	// A = base^r
	A = zp256.ScalarMul(base, r)
	// c = H(A,r)
	c := HashSchnorr(A, R)
	// z = r + c*x
	z = ffmath.AddMod(r, ffmath.MultiplyMod(c, x, Order), Order)
	return z, A
}

// check base^z = A * r^c
func Verify(z *big.Int, A *P256, R *P256, base *P256) bool {
	// cal c = H(A,r)
	c := HashSchnorr(A, R)
	l := zp256.ScalarMul(base, z)
	r := zp256.Add(A, zp256.ScalarMul(R, c))
	return zp256.Equal(l, r)
}
