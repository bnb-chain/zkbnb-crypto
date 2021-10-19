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

package zsha256

func Sha256Hash(cs *ConstraintSystem, data []Variable, nBits int) {
	nBlocks := ((nBits + 64) / 512) + 1
	var (
		paddedIn []Variable
	)
	for k := 0; k < nBits; k++ {
		paddedIn = append(paddedIn, data[k])
	}
	paddedIn = append(paddedIn, cs.Constant(1))
	for k := nBits + 1; k < nBlocks*512-64; k++ {
		paddedIn = append(paddedIn, cs.Constant(0))
	}
	for k := 0; k < 64; k++ {
		paddedIn[nBlocks*512-k-1] = cs.Constant((nBits >> k) & 1)
	}
}
