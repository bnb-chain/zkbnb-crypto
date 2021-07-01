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

package transactions

func setFixedMerkleProofs(proof [][]byte) [AccountMerkleLevels][]byte {
	var res [AccountMerkleLevels][]byte
	for i := 0; i < AccountMerkleLevels; i++ {
		res[i] = proof[i]
	}
	return res
}

func setFixedMerkleProofsHelper(proof []int) [AccountMerkleLevels - 1]int {
	var res [AccountMerkleLevels - 1]int
	for i := 0; i < AccountMerkleLevels-1; i++ {
		res[i] = proof[i]
	}
	return res
}
