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
	"bytes"
	"fmt"
	"hash"
	"math/big"
)

/*
	Tree: sparse merkle tree
*/
type Tree struct {
	// leaves
	Leaves []*Node
	// root val
	Root []byte
	// root node
	RootNode *Node
	// height
	Height int
	// leaves count
	NbLeavesCount int64
	// hash function
	HashFunc hash.Hash
}

/*
	Node: node in the tree
*/
type Node struct {
	// node value
	Value []byte
	// left node
	Left *Node
	// right node
	Right *Node
	// parent node
	Parent *Node
	// height
	Height int
}

/*
	CreateLeaves: transfer hashState to []node
	@hashState: hash state
*/
func CreateLeaves(hashState [][]byte) []*Node {
	// construct leaves
	var leaves []*Node
	for i := 0; i < len(hashState); i++ {
		node := &Node{
			Value:  hashState[i],
			Left:   nil,
			Right:  nil,
			Parent: nil,
			Height: 0,
		}
		leaves = append(leaves, node)
	}
	return leaves
}

/*
	NewTree: build sparse merkle trees
	@leaves: nodes
*/
func NewTree(leaves []*Node, h hash.Hash) (*Tree, error) {
	// leaves count should be the power of 2
	size := int64(len(leaves))
	if !IsPowerOfTwo(size) {
		return nil, ErrInvalidLeavesSize
	}
	// construct tree
	rootNode := buildTree(leaves, h)
	tree := &Tree{
		Leaves:        leaves,
		Root:          rootNode.Value,
		RootNode:      rootNode,
		Height:        rootNode.Height,
		NbLeavesCount: size,
		HashFunc:      h,
	}
	return tree, nil
}

/*
	buildTree: internal function to build merkle tree
*/
func buildTree(nodes []*Node, h hash.Hash) *Node {
	if len(nodes) == 1 {
		return nodes[0]
	}
	var upperNodes []*Node
	for i := 0; i < len(nodes); i += 2 {
		// construct parent node
		node := &Node{
			Value:  sumNode(nodes[i].Value, nodes[i+1].Value, h),
			Left:   nodes[i],
			Right:  nodes[i+1],
			Parent: nil,
			Height: nodes[i].Height + 1,
		}
		// modify lower nodes
		node.Left.Parent = node
		node.Right.Parent = node
		upperNodes = append(upperNodes, node)
	}
	return buildTree(upperNodes, h)
}

/*
	sumNode: compute sum of the node
*/
func sumNode(l, r []byte, h hash.Hash) []byte {
	h.Reset()
	h.Write(l)
	h.Write(r)
	return h.Sum([]byte{})
}

/*
	BuildMerkleProofs: build merkle proofs for the index
	@index: index
*/
func (tree *Tree) BuildMerkleProofs(index int64) (merkleProofs [][]byte, helperMerkleProofs []int, err error) {
	if index >= tree.NbLeavesCount || index < 0 {
		return nil, nil, ErrInvalidIndex
	}
	current := tree.Leaves[index]
	merkleProofs = append(merkleProofs, current.Value)
	i := 0
	prev := *current
	// get node recursively
	for current.Parent != nil {
		current = current.Parent
		if bytes.Equal(current.Left.Value, prev.Value) {
			merkleProofs = append(merkleProofs, current.Right.Value)
			helperMerkleProofs = append(helperMerkleProofs, 0)
		} else if bytes.Equal(current.Right.Value, prev.Value) {
			merkleProofs = append(merkleProofs, current.Left.Value)
			helperMerkleProofs = append(helperMerkleProofs, 1)
		} else {
			return nil, nil, ErrInvalidMerkleTree
		}
		i++
		prev = *current
	}
	return merkleProofs, helperMerkleProofs, nil
}

/*
	VerifyMerkleProofs: verify merkle proofs
	@inclusionProofs: inclusion proofs
	@helperProofs: helper function
*/
func (tree *Tree) VerifyMerkleProofs(inclusionProofs [][]byte, helperProofs []int) bool {
	if len(inclusionProofs) != len(helperProofs)+1 {
		return false
	}
	root := tree.Root
	node := inclusionProofs[0]
	for i := 1; i < len(inclusionProofs); i++ {
		switch helperProofs[i-1] {
		case 0:
			node = sumNode(node, inclusionProofs[i], tree.HashFunc)
			continue
		case 1:
			node = sumNode(inclusionProofs[i], node, tree.HashFunc)
			continue
		default:
			return false
		}
	}
	return bytes.Equal(root, node)
}

/*
	UpdateNode: update node
	@index: index
	@val: new value
*/
func (tree *Tree) UpdateNode(index int64, val []byte) error {
	// index should smaller than NbLeavesCount
	if index > tree.NbLeavesCount || index < 0 {
		return ErrInvalidIndex
	}
	current := tree.Leaves[index]
	current.Value = val
	// update node recursively
	for current.Parent != nil {
		current = current.Parent
		current.Value = sumNode(current.Left.Value, current.Right.Value, tree.HashFunc)
	}
	tree.Root = current.Value
	return nil
}
