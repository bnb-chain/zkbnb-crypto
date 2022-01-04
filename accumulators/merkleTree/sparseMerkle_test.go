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
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"
	"time"
	"zecrey-crypto/hash/bn254/zmimc"
)

func MockState(size int) [][]byte {
	//if !IsPowerOfTwo(int64(size)) {
	//	panic("err size")
	//}
	var hashState [][]byte
	h := zmimc.Hmimc
	for i := 0; i < size; i++ {
		h.Reset()
		h.Write([]byte(strconv.Itoa(i)))
		hashState = append(hashState, h.Sum([]byte{}))
	}
	return hashState
}

func ToString(buf []byte) string {
	return hex.EncodeToString(buf)
}

func TestNewTree(t *testing.T) {
	elapse := time.Now()
	hashState := MockState(6)
	fmt.Println(time.Since(elapse))
	leaves := CreateLeaves(hashState)
	elapse = time.Now()
	h := mimc.NewMiMC(SEED)
	nilHash := h.Sum([]byte{})
	fmt.Println("nil hash:", common.Bytes2Hex(nilHash))
	h.Reset()
	tree, err := NewTree(leaves, 5, nilHash, h)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("BuildTree tree time:", time.Since(elapse))
	fmt.Println("height:", tree.MaxHeight)
	fmt.Println("root:", ToString(tree.RootNode.Value))
	fmt.Println("nil root:", ToString(tree.NilHashValueConst[0]))
	elapse = time.Now()
	// verify index belongs to len(t.leaves)
	merkleProofs, helperMerkleProofs, err := tree.BuildMerkleProofs(4)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("len:", len(merkleProofs))
	fmt.Println("BuildTree proofs time:", time.Since(elapse))
	fmt.Println("merkle proof helper:", helperMerkleProofs)
	res := tree.VerifyMerkleProofs(merkleProofs, helperMerkleProofs)
	assert.Equal(t, res, true, "BuildTree merkle proofs successfully")
	// if len(t.leaves) % 2 != 0 && index == len(t.leaves) + 1
	merkleProofs, helperMerkleProofs, err = tree.BuildMerkleProofs(0)
	if err != nil {
		t.Fatal(err)
	}
	res = tree.VerifyMerkleProofs(merkleProofs, helperMerkleProofs)
	fmt.Println("merkle proof helper:", helperMerkleProofs)
	assert.Equal(t, res, true, "BuildTree merkle proofs successfully")
	// verify index >= len(t.leaves) + 1
	fmt.Println("111:", tree.NilHashValueConst[0])
	merkleProofs, helperMerkleProofs, err = tree.BuildMerkleProofs(2)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("before proofs:", merkleProofs)
	res = tree.VerifyMerkleProofs(merkleProofs, helperMerkleProofs)
	fmt.Println("merkle proof helper:", helperMerkleProofs)
	assert.Equal(t, res, true, "BuildTree merkle proofs successfully")
	h.Reset()
	h.Write([]byte("modify"))
	nVal := h.Sum([]byte{})
	fmt.Println("nVal:", nVal)
	err = tree.Update(6, nVal)
	if err != nil {
		t.Fatal(err)
	}
	merkleProofs, helperMerkleProofs, err = tree.BuildMerkleProofs(7)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("after proofs:", merkleProofs)
	fmt.Println("merkle proof helper:", helperMerkleProofs)

	merkleProofs, helperMerkleProofs, err = tree.BuildMerkleProofs(3)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("merkle proof helper:", helperMerkleProofs)

	merkleProofs, helperMerkleProofs, err = tree.BuildMerkleProofs(4)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("merkle proof helper:", helperMerkleProofs)
	//var oldState []byte
	//for i := 0; i < len(hashState); i++ {
	//	oldState = append(oldState, hashState[i]...)
	//}
	//var buf bytes.Buffer
	//buf.Write(oldState)
	//h := mimc.NewMiMC(SEED)
	//root, inclusionProofs, numLeaves, err := merkletree.BuildReaderProof(&buf, h, h.Size(), 7)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//helper := merkle.GenerateProofHelper(inclusionProofs, 7, numLeaves)
	//fmt.Println(ToString(tree.Root))
	//fmt.Println(ToString(root))
	//fmt.Println(ToString(merkleProofs[2]))
	//fmt.Println(ToString(inclusionProofs[2]))
	//fmt.Println(helperMerkleProofs[2])
	//fmt.Println(helper[2])

}

func TestNewEmptyTree(t *testing.T) {
	h := mimc.NewMiMC(SEED)
	nilHash := h.Sum([]byte{})
	tree, err := NewEmptyTree(5, nilHash, zmimc.Hmimc)
	if err != nil {
		t.Fatal(err)
	}
	merkleProofs, merkleProofsHelper, err := tree.BuildMerkleProofs(5)
	if err != nil {
		t.Fatal(err)
	}
	isValid := tree.VerifyMerkleProofs(merkleProofs, merkleProofsHelper)
	assert.Equal(t, true, isValid, "invalid proof")
	h.Reset()
	h.Write([]byte("1"))
	nVal := h.Sum([]byte{})
	err = tree.Update(0, nVal)
	if err != nil {
		t.Fatal(err)
	}
	merkleProofs, merkleProofsHelper, err = tree.BuildMerkleProofs(0)
	isValid = tree.VerifyMerkleProofs(merkleProofs, merkleProofsHelper)
	assert.Equal(t, true, isValid, "invalid proof")
}
