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

package merkleTree

import (
	"github.com/bnb-chain/zkbnb-crypto/hash/bn254/zmimc"
)

/*
IsPowerOfTwo returns true for arguments that are a power of 2, false otherwise.
https://stackoverflow.com/a/600306/844313
*/
func IsPowerOfTwo(x int64) bool {
	return (x != 0) && ((x & (x - 1)) == 0)
}

/*
	CopyMerkleProofs: deep copy for merkle proofs
*/
func CopyMerkleProofs(a [][]byte) [][]byte {
	res := make([][]byte, len(a))
	for i := 0; i < len(a); i++ {
		res[i] = make([]byte, len(a[i]))
		copy(res[i], a[i])
	}
	return res
}

func MockNilHashState(size int) [][]byte {
	var hashState [][]byte
	h := zmimc.Hmimc
	for i := 0; i < size; i++ {
		h.Reset()
		hashState = append(hashState, h.Sum([]byte{}))
	}
	return hashState
}
