/*
 * Copyright © 2022 ZkBNB Protocol
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

package types

import "github.com/consensys/gnark/std/hash/poseidon"

/*
VerifyMerkleProof: takes a Merkle root, a proofSet, and a proofIndex and returns

	true if the first element of the proof set is a leaf of data in the Merkle
	root. False is returned if the proof set or Merkle root is nil, and if
	'numLeaves' equals 0.
*/
func VerifyMerkleProof(api API, isEnabled Variable, merkleRoot Variable, node Variable, proofSet, helper []Variable) {
	for i := 0; i < len(proofSet); i++ {
		api.AssertIsBoolean(helper[i])
		d1 := api.Select(helper[i], proofSet[i], node)
		d2 := api.Select(helper[i], node, proofSet[i])
		node = nodeSumPoseidon(api, d1, d2)
	}
	// Compare our calculated Merkle root to the desired Merkle root.
	IsVariableEqual(api, isEnabled, merkleRoot, node)
}

func UpdateMerkleProof(api API, node Variable, proofSet, helper []Variable) (root Variable) {
	for i := 0; i < len(proofSet); i++ {
		api.AssertIsBoolean(helper[i])
		d1 := api.Select(helper[i], proofSet[i], node)
		d2 := api.Select(helper[i], node, proofSet[i])
		node = nodeSumPoseidon(api, d1, d2)
	}
	root = node
	return root
}

// nodeSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func nodeSum(h MiMC, a, b Variable) Variable {
	h.Write(a)
	h.Write(b)
	res := h.Sum()
	return res
}

func nodeSumPoseidon(api API, a, b Variable) Variable {
	res := poseidon.Poseidon(api, a, b)
	return res
}
