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

package bulletProofs

import (
	"math/big"
	"zecrey-crypto/ffmath"
)

func DecomposeVec(xs []*big.Int, u int64, l int64) ([]int64, error) {
	var result []int64
	for i := 0; i < len(xs); i++ {
		vec, err := Decompose(xs[i], u, l)
		if err != nil {
			return nil, err
		}
		result = append(result, vec...)
	}
	return result, nil
}

/*
delta(y,z) = (z-z^2) . < 1^n, y^n > - \sum_{j=1}^m z^{j+2} . < 1^n, 2^n >
*/
func aggDelta(y, z *big.Int, N int64, m int64) (*big.Int, error) {
	var (
		result *big.Int
	)
	nm := N * m
	// < 1^{nm}, y^{nm} >
	v1m, err := VectorCopy(big.NewInt(1), nm)
	if err != nil {
		return nil, err
	}
	vy := powerOfVec(y, nm)
	sp1y, err := ScalarVecMul(v1m, vy)
	if err != nil {
		return nil, err
	}

	// < 1^n, 2^n >
	v1n, err := VectorCopy(big.NewInt(1), N)
	if err != nil {
		return nil, err
	}
	p2n := powerOfVec(big.NewInt(2), N)
	sp12, err := ScalarVecMul(v1n, p2n)
	if err != nil {
		return nil, err
	}

	// delta(y,z) = (z-z^2) . < 1^{nm}, y^{nm} > - \sum_{j=1}^m z^{j+2} . < 1^n, 2^n >
	z2 := ffmath.MultiplyMod(z, z, Order)
	tz := new(big.Int).Set(z2)
	result = ffmath.SubMod(z, z2, Order)
	result = ffmath.MultiplyMod(result, sp1y, Order)
	for j := int64(1); j <= m; j++ {
		tz = ffmath.MultiplyMod(tz, z, Order)
		result = ffmath.SubMod(result, ffmath.MultiplyMod(tz, sp12, Order), Order)
	}

	return result, nil
}
