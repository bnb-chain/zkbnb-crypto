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

package commitRange

import (
	"math/big"
	"zecrey-crypto/ffmath"
)

/*
	toBinary receives as input a bigint x and outputs an array of integers such that
	x = sum(xi.2^i), i.e. it returns the decomposition of x into base 2.
*/
func toBinary(x *big.Int, l int64) ([]*big.Int, error) {
	var (
		resultBigInt []*big.Int
		i            int64
	)
	resultBigInt = make([]*big.Int, l)
	uInt := big.NewInt(int64(2))
	i = 0
	for i < l {
		resultBigInt[i] = big.NewInt(ffmath.Mod(x, uInt).Int64())
		x = ffmath.Div(x, uInt)
		i = i + 1
	}
	return resultBigInt, nil
}

/*
powerOf returns a vector composed by powers of x.
*/
func PowerOfVec(y *big.Int, n int64) []*big.Int {
	var (
		i      int64
		result []*big.Int
	)
	result = make([]*big.Int, n)
	current := big.NewInt(1)
	i = 0
	for i < n {
		result[i] = current
		current = ffmath.MultiplyMod(y, current, Order)
		i++
	}
	return result
}
