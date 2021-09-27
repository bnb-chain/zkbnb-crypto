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

package ctrange

import (
	"math"
)

/*
	toBinary receives as input a bigint x and outputs an array of integers such that
	x = sum(xi.2^i), i.e. it returns the decomposition of x into base 2.
*/
func toBinary(x int64, l int64) ([]int, error) {
	var (
		resultBigInt []int
		i            int64
	)
	resultBigInt = make([]int, l)
	two := float64(2)
	i = 0
	for i < l {
		resultBigInt[i] = int(math.Mod(float64(x), two))
		x = x / int64(two)
		i = i + 1
	}
	return resultBigInt, nil
}
