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

package linear

import (
	"math/big"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/ffmath"
)

type Point = curve.Point

var (
	G = curve.G
)

// u = \prod_{i=1}^n g_{i}^{x_i}
func Prove(xArr []*big.Int, gArr, uArr []*Point) (zArr []*big.Int, UtArr []*Point) {
	m := len(uArr)
	n := len(xArr)
	var xtArr []*big.Int
	for i := 0; i < n; i++ {
		xti := curve.RandomValue()
		xtArr = append(xtArr, xti)
	}
	if xtArr == nil {
		return nil, nil
	}
	for i := 0; i < m; i++ {
		var Uti *Point
		for j := 0; j < n; j++ {
			if j == 0 {
				Uti = curve.ScalarMul(gArr[i*n+j], xtArr[j])
				continue
			}
			Uti = curve.Add(Uti, curve.ScalarMul(gArr[i*n+j], xtArr[j]))
		}
		UtArr = append(UtArr, Uti)
	}
	// c = HashLinear
	c := HashLinear(UtArr, uArr)
	for i := 0; i < n; i++ {
		zi := ffmath.Add(xtArr[i], ffmath.Multiply(c, xArr[i]))
		zArr = append(zArr, zi)
	}
	return zArr, UtArr
}

func Verify(zArr []*big.Int, gArr, uArr, UtArr []*Point) bool {
	n := len(zArr)
	m := len(uArr)
	// cal c
	c := HashLinear(UtArr, uArr)
	for i := 0; i < m; i++ {
		var l, r *Point
		for j := 0; j < n; j++ {
			if j == 0 {
				l = curve.ScalarMul(gArr[i*n+j], zArr[j])
				continue
			}
			l = curve.Add(l, curve.ScalarMul(gArr[i*n+j], zArr[j]))
		}
		r = curve.Add(UtArr[i], curve.ScalarMul(uArr[i], c))
		if l == nil || r == nil || !l.Equal(r) {
			return false
		}
	}
	return true
}
