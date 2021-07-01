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

package std

// leafSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func leafSum(cs *ConstraintSystem, h MiMC, data Variable) Variable {

	res := h.Hash(cs, data)

	return res
}

// nodeSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func nodeSum(cs *ConstraintSystem, h MiMC, a, b Variable) Variable {

	res := h.Hash(cs, a, b)

	return res
}

/*
	VerifyMerkleProof: takes a Merkle root, a proofSet, and a proofIndex and returns
	 true if the first element of the proof set is a leaf of data in the Merkle
	 root. False is returned if the proof set or Merkle root is nil, and if
	 'numLeaves' equals 0.
*/
func VerifyMerkleProof(cs *ConstraintSystem, isEnabled Variable, h MiMC, merkleRoot Variable, proofSet, helper []Variable) {

	sum := leafSum(cs, h, proofSet[0])

	for i := 1; i < len(proofSet); i++ {
		cs.AssertIsBoolean(helper[i-1])
		d1 := cs.Select(helper[i-1], sum, proofSet[i])
		d2 := cs.Select(helper[i-1], proofSet[i], sum)
		sum = nodeSum(cs, h, d1, d2)
	}
	// Compare our calculated Merkle root to the desired Merkle root.
	IsVariableEqual(cs, isEnabled, sum, merkleRoot)

}

func SetMerkleProofsWitness(proofs [AccountMerkleLevels][]byte) (witness [AccountMerkleLevels]Variable) {
	for i := 0; i < AccountMerkleLevels; i++ {
		witness[i].Assign(proofs[i])
	}
	return witness
}

func SetMerkleProofsHelperWitness(proofs [AccountMerkleLevels - 1]int) (witness [AccountMerkleLevels - 1]Variable) {
	for i := 0; i < AccountMerkleLevels-1; i++ {
		witness[i].Assign(proofs[i])
	}
	return witness
}
