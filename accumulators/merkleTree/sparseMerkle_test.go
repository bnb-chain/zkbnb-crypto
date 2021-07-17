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
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"
	"time"
	"zecrey-crypto/hash/bn254/zmimc"
)

func mockState(size int) [][]byte {
	if !IsPowerOfTwo(int64(size)) {
		panic("err size")
	}
	var hashState [][]byte
	h := zmimc.Hmimc
	for i := 0; i < size; i++ {
		h.Reset()
		h.Write([]byte(strconv.Itoa(i)))
		hashState = append(hashState, h.Sum([]byte{}))
	}
	return hashState
}

func toString(buf []byte) string {
	return hex.EncodeToString(buf)
}

func TestNewTree(t *testing.T) {
	elapse := time.Now()
	hashState := mockState(131072)
	fmt.Println(time.Since(elapse))
	leaves := CreateLeaves(hashState)
	elapse = time.Now()
	h := mimc.NewMiMC(SEED)
	tree, err := NewTree(leaves, h)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("build tree time:", time.Since(elapse))
	fmt.Println(tree.Height)
	fmt.Println(toString(tree.Root))
	fmt.Println(tree.RootNode.Left.Height)
	fmt.Println(tree.RootNode.Right.Right)
	fmt.Println(tree.RootNode.Left.Parent.Value)
	elapse = time.Now()
	merkleProofs, helperMerkleProofs, err := tree.BuildMerkleProofs(473)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("build proofs time:", time.Since(elapse))
	res := tree.VerifyMerkleProofs(merkleProofs, helperMerkleProofs)
	assert.Equal(t, res, true, "build merkle proofs successfully")
	merkleProofs, helperMerkleProofs, err = tree.BuildMerkleProofs(32)
	if err != nil {
		t.Fatal(err)
	}
	res = tree.VerifyMerkleProofs(merkleProofs, helperMerkleProofs)
	assert.Equal(t, res, true, "build merkle proofs successfully")
	h.Reset()
	h.Write([]byte("modify"))
	err = tree.UpdateNode(32, h.Sum([]byte{}))
	if err != nil {
		t.Fatal(err)
	}
	merkleProofs, helperMerkleProofs, err = tree.BuildMerkleProofs(32)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, res, true, "update tree and build merkle proofs successfully")

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
	//fmt.Println(toString(tree.Root))
	//fmt.Println(toString(root))
	//fmt.Println(toString(merkleProofs[2]))
	//fmt.Println(toString(inclusionProofs[2]))
	//fmt.Println(helperMerkleProofs[2])
	//fmt.Println(helper[2])

}
