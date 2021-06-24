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
	"zecrey-crypto/ecc/zp256"
	"zecrey-crypto/ffmath"
)

type P256 = zp256.P256

// u = \prod_{i=1}^n g_{i}^{x_i}
func Prove(xArr []*big.Int, gArr, uArr []*P256) (zArr []*big.Int, UtArr []*P256) {
	m := len(uArr)
	n := len(xArr)
	var xtArr []*big.Int
	for i := 0; i < n; i++ {
		xti := zp256.RandomValue()
		xtArr = append(xtArr, xti)
	}
	for i := 0; i < m; i++ {
		var Uti *P256
		for j := 0; j < n; j++ {
			if j == 0 {
				Uti = zp256.ScalarMul(gArr[i*n+j], xtArr[j])
				continue
			}
			Uti = zp256.Add(Uti, zp256.ScalarMul(gArr[i*n+j], xtArr[j]))
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

func Verify(zArr []*big.Int, gArr, uArr, UtArr []*P256) bool {
	n := len(zArr)
	m := len(uArr)
	// cal c
	c := HashLinear(UtArr, uArr)
	for i := 0; i < m; i++ {
		var l, r *P256
		for j := 0; j < n; j++ {
			if j == 0 {
				l = zp256.ScalarMul(gArr[i*n+j], zArr[j])
				continue
			}
			l = zp256.Add(l, zp256.ScalarMul(gArr[i*n+j], zArr[j]))
		}
		r = zp256.Add(UtArr[i], zp256.ScalarMul(uArr[i], c))
		if !zp256.Equal(l, r) {
			return false
		}
	}
	return true
}
