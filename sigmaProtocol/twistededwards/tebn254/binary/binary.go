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
	"github.com/zecrey-labs/zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
)

type Point = curve.Point

var (
	G = curve.G
)

func Prove(m int, r *big.Int) (ca *Point, cb *Point, f *big.Int, za *big.Int, zb *big.Int, err error) {
	if m != 0 && m != 1 {
		return nil, nil, nil, nil, nil, errors.New("invalid m, m should be binary")
	}
	// a,s,t \gets_R \mathbb{Z}_p
	a := curve.RandomValue()
	s := curve.RandomValue()
	t := curve.RandomValue()
	ca, err = pedersen.Commit(a, s, G, curve.H)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	cb, err = pedersen.Commit(ffmath.Multiply(a, big.NewInt(int64(m))), t, G, curve.H)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	// challenge
	x := HashChallenge(ca, cb)
	// f = mx + a
	f = ffmath.Add(ffmath.Multiply(x, big.NewInt(int64(m))), a)
	// za = rx + s
	za = ffmath.Add(ffmath.Multiply(r, x), s)
	// zb = r(x - f) + t
	zb = ffmath.Sub(x, f)
	zb = ffmath.Multiply(r, zb)
	zb = ffmath.Add(zb, t)
	return ca, cb, f, za, zb, nil
}

func Verify(c, ca, cb *Point, f, za, zb *big.Int) (bool, error) {
	// c^x ca == Com(f,za)
	r1, err := pedersen.Commit(f, za, G, curve.H)
	if err != nil {
		return false, err
	}
	// challenge
	x := HashChallenge(ca, cb)
	l1 := curve.Add(curve.ScalarMul(c, x), ca)
	l1r1 := l1.Equal(r1)
	if !l1r1 {
		return false, nil
	}
	// c^{x-f} cb == Com(0,zb)
	r2, _ := pedersen.Commit(big.NewInt(0), zb, G, curve.H)
	l2 := curve.Add(curve.ScalarMul(c, ffmath.Sub(x, f)), cb)
	l2r2 := l2.Equal(r2)
	return l2r2, nil
}
