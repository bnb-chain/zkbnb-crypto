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

package binary

import (
	"errors"
	"math/big"
	"zecrey-crypto/commitment/secp256k1/pedersen"
	"zecrey-crypto/ecc/zp256"
	"zecrey-crypto/ffmath"
)

type P256 = zp256.P256

func Prove(m int, r *big.Int) (ca *P256, cb *P256, f *big.Int, za *big.Int, zb *big.Int, err error) {
	if m != 0 && m != 1 {
		return nil, nil, nil, nil, nil, errors.New("invalid m, m should be binary")
	}
	// a,s,t \gets_R \mathbb{Z}_p
	a := zp256.RandomValue()
	s := zp256.RandomValue()
	t := zp256.RandomValue()
	ca = pedersen.Commit(a, s, zp256.Base(), zp256.H)
	cb = pedersen.Commit(ffmath.Multiply(a, big.NewInt(int64(m))), t, zp256.Base(), zp256.H)
	// challenge
	x := HashChallenge(ca, cb)
	// f = mx + a
	f = ffmath.AddMod(ffmath.Multiply(x, big.NewInt(int64(m))), a, Order)
	// za = rx + s
	za = ffmath.AddMod(ffmath.MultiplyMod(r, x, Order), s, Order)
	// zb = r(x - f) + t
	zb = ffmath.SubMod(x, f, Order)
	zb = ffmath.MultiplyMod(r, zb, Order)
	zb = ffmath.AddMod(zb, t, Order)
	return ca, cb, f, za, zb, nil
}

func Verify(c, ca, cb *P256, f, za, zb *big.Int) bool {
	// c^x ca == Com(f,za)
	r1 := pedersen.Commit(f, za, zp256.Base(), zp256.H)
	// challenge
	x := HashChallenge(ca, cb)
	l1 := zp256.Add(zp256.ScalarMul(c, x), ca)
	l1r1 := zp256.Equal(l1, r1)
	if !l1r1 {
		return false
	}
	// c^{x-f} cb == Com(0,zb)
	r2 := pedersen.Commit(big.NewInt(0), zb, zp256.Base(), zp256.H)
	l2 := zp256.Add(zp256.ScalarMul(c, ffmath.SubMod(x, f, Order)), cb)
	l2r2 := zp256.Equal(l2, r2)
	if !l2r2 {
		return false
	}
	return true
}
