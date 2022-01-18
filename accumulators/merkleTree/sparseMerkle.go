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
	"errors"
	"fmt"
	"hash"
	"log"
)

const (
	Left  = 0
	Right = 1
)

/*
	Tree: sparse merkle tree
*/
type Tree struct {
	// root Node
	RootNode *Node
	// leaves
	Leaves []*Node
	// max height
	MaxHeight int
	// nil hash tree
	NilHashValueConst [][]byte
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

func CreateLeafNode(hashVal []byte) *Node {
	return &Node{
		Value:  hashVal,
		Left:   nil,
		Right:  nil,
		Parent: nil,
		Height: 0,
	}
}

func (t *Tree) InitNilHashValueConst() (err error) {
	nilHash := t.NilHashValueConst[0]
	for i := 1; i <= t.MaxHeight; i++ {
		var (
			nHash []byte
		)
		nHash = t.HashSubTrees(nilHash, nilHash)
		t.NilHashValueConst[i] = nHash
		nilHash = nHash
	}
	return err
}

func NewEmptyTree(maxHeight int, nilHash []byte, hFunc hash.Hash) (*Tree, error) {
	root := &Node{
		Value:  nilHash,
		Left:   nil,
		Right:  nil,
		Parent: nil,
		Height: maxHeight,
	}
	// init nil hash values for different heights
	nilHashValueConst := make([][]byte, maxHeight+1)
	nilHashValueConst[0] = nilHash
	// init tree
	tree := &Tree{
		RootNode:          root,
		MaxHeight:         maxHeight,
		Leaves:            *new([]*Node),
		NilHashValueConst: nilHashValueConst,
		HashFunc:          hFunc,
	}
	err := tree.InitNilHashValueConst()
	if err != nil {
		errInfo := fmt.Sprintf("[smt.NewEmptyTree] InitNilHashValueConst error: %s", err.Error())
		log.Println(errInfo)
		return nil, errors.New(errInfo)
	}
	return tree, nil
}

/*
	func: NewTree
	params: leaves []*Node, maxHeight int, nilHash []byte, hFunc hash.Hash
    desp: Use leaf nodes to initialize the tree,
          and call the BuildTree method through the root to initialize the hash value of the entire tree
*/
func NewTreeByMap(leaves map[int64]*Node, maxHeight int, nilHash []byte, hFunc hash.Hash) (*Tree, error) {
	// define variables
	var (
		root *Node
	)
	// empty tree
	if leaves == nil {
		return NewEmptyTree(maxHeight, nilHash, hFunc)
	}
	// construct root node
	root = &Node{
		Value:  nilHash,
		Left:   nil,
		Right:  nil,
		Parent: nil,
		Height: maxHeight,
	}
	// init nil hash values for different heights
	nilHashValueConst := make([][]byte, maxHeight+1)
	nilHashValueConst[0] = nilHash
	// scan map
	maxIndex := int64(0)
	for index, _ := range leaves {
		if index > maxIndex {
			maxIndex = index
		}
	}
	var nodes []*Node
	for i := int64(0); i <= maxIndex; i++ {
		if leaves[i] != nil {
			nodes = append(nodes, leaves[i])
		} else {
			nodes = append(nodes, &Node{
				Value:  nilHash,
				Left:   nil,
				Right:  nil,
				Parent: nil,
				Height: 0,
			})
		}
	}
	// init tree
	tree := &Tree{
		RootNode:          root,
		Leaves:            nodes,
		MaxHeight:         maxHeight,
		NilHashValueConst: nilHashValueConst,
		HashFunc:          hFunc,
	}
	err := tree.InitNilHashValueConst()
	if err != nil {
		errInfo := fmt.Sprintf("[smt.NewTree] InitNilHashValueConst error: %s", err.Error())
		log.Println(errInfo)
		return nil, errors.New(errInfo)
	}

	err = tree.BuildTree(tree.Leaves)
	if err != nil {
		log.Println("[NewTree] unable to build tree: ", err)
		return nil, err
	}
	return tree, nil
}

/*
	func: NewTree
	params: leaves []*Node, maxHeight int, nilHash []byte, hFunc hash.Hash
    desp: Use leaf nodes to initialize the tree,
          and call the BuildTree method through the root to initialize the hash value of the entire tree
*/
func NewTree(leaves []*Node, maxHeight int, nilHash []byte, hFunc hash.Hash) (*Tree, error) {
	// define variables
	var (
		root *Node
	)
	// empty tree
	if len(leaves) == 0 || leaves == nil {
		return NewEmptyTree(maxHeight, nilHash, hFunc)
	}
	// construct root node
	root = &Node{
		Value:  nilHash,
		Left:   nil,
		Right:  nil,
		Parent: nil,
		Height: maxHeight,
	}
	// init nil hash values for different heights
	nilHashValueConst := make([][]byte, maxHeight+1)
	nilHashValueConst[0] = nilHash
	// init tree
	tree := &Tree{
		RootNode:          root,
		Leaves:            leaves,
		MaxHeight:         maxHeight,
		NilHashValueConst: nilHashValueConst,
		HashFunc:          hFunc,
	}
	err := tree.InitNilHashValueConst()
	if err != nil {
		errInfo := fmt.Sprintf("[smt.NewTree] InitNilHashValueConst error: %s", err.Error())
		log.Println(errInfo)
		return nil, errors.New(errInfo)
	}

	err = tree.BuildTree(tree.Leaves)
	if err != nil {
		log.Println("[NewTree] unable to build tree: ", err)
		return nil, err
	}
	return tree, nil
}

/*
	HashSubTrees: hash sub-tree nodes
*/
func (t *Tree) HashSubTrees(l []byte, r []byte) []byte {
	t.HashFunc.Reset()
	t.HashFunc.Write(l)
	t.HashFunc.Write(r)
	val := t.HashFunc.Sum([]byte{})
	return val
}

/*
	BuildTree: build sparse merkle tree
*/
func (t *Tree) BuildTree(nodes []*Node) (err error) {
	// get to the max height
	if len(nodes) == 0 {
		log.Println("[BuildTree] smt BuildTree error, nodes length == 0")
		return errors.New("[BuildTree] nodes length == 0")
	} else {
		if nodes[0].Height == t.MaxHeight && len(nodes) == 1 {
			t.RootNode = nodes[0]
			return nil
		}
	}
	if len(nodes)%2 != 0 {
		nodes = append(nodes, &Node{
			Value:  t.NilHashValueConst[nodes[0].Height],
			Left:   nil,
			Right:  nil,
			Parent: nil,
			Height: nodes[0].Height,
		})
	}
	var parents []*Node
	for i := 0; i < len(nodes); i += 2 {
		nodes[i].Parent = &Node{
			Value:  t.HashSubTrees(nodes[i].Value, nodes[i+1].Value),
			Left:   nodes[i],
			Right:  nodes[i+1],
			Parent: nil,
			Height: nodes[i].Height + 1,
		}
		nodes[i+1].Parent = nodes[i].Parent

		parents = append(parents, nodes[i].Parent)
	}
	err = t.BuildTree(parents)
	return err
}

/*
	BuildMerkleProofs: construct merkle proofs
*/
func (t *Tree) BuildMerkleProofs(index int64) (
	rMerkleProof [][]byte,
	rProofHelper []int,
	err error,
) {
	var proofs [][]byte
	var proofHelpers []int
	if index >= (1 << t.MaxHeight) {
		errInfo := fmt.Sprintf("[BuildMerkleProofs] index error, index: %v is bigger than tree capacity: %v.",
			index, 1<<t.MaxHeight)
		log.Println(errInfo)
		return nil, nil, errors.New(errInfo)
	}
	// empty tree
	if len(t.Leaves) == 0 {
		rProofHelper = make([]int, t.MaxHeight)
		for i := 0; i < t.MaxHeight; i++ {
			rProofHelper[i] = 0
		}
		return t.NilHashValueConst, rProofHelper, nil
	}
	// if index belongs to leaves
	if index < int64(len(t.Leaves)) {
		node := t.Leaves[index]
		proofs = append(proofs, node.Value)
		for node.Parent != nil {
			if node.Parent.Left == node {
				if node.Parent.Right == nil {
					proofs = append(proofs, t.NilHashValueConst[node.Height])
				} else {
					proofs = append(proofs, node.Parent.Right.Value)
				}
				proofHelpers = append(proofHelpers, Left)
			} else if node.Parent.Right == node {
				proofs = append(proofs, node.Parent.Left.Value)
				proofHelpers = append(proofHelpers, Right)
			} else {
				errInfo := fmt.Sprintf("[BuildMerkleProofs] node error, node is neither left node nor right node.")
				log.Println(errInfo)
				return nil, nil, errors.New(errInfo)
			}
			node = node.Parent
		}
	} else {
		// add itself
		proofs = append(proofs, t.NilHashValueConst[0])
		// get last index
		lastIndex := int64(len(t.Leaves) - 1)
		// get last leave node
		node := t.Leaves[lastIndex]
		for lastIndex+1 != index {
			proofs = append(proofs, t.NilHashValueConst[node.Height])
			if index%2 == 0 {
				proofHelpers = append(proofHelpers, Right)
			} else {
				proofHelpers = append(proofHelpers, Left)
			}
			// update value
			lastIndex /= 2
			index /= 2
			node = node.Parent
		}
		proofs = append(proofs, node.Value)
		proofHelpers = append(proofHelpers, Right)
		node = node.Parent
		for node.Parent != nil {
			if node.Parent.Left == node {
				if node.Parent.Right == nil {
					proofs = append(proofs, t.NilHashValueConst[node.Height])
				} else {
					proofs = append(proofs, node.Parent.Right.Value)
				}
				proofHelpers = append(proofHelpers, Left)
			} else if node.Parent.Right == node {
				proofs = append(proofs, node.Parent.Left.Value)
				proofHelpers = append(proofHelpers, Right)
			} else {
				errInfo := fmt.Sprintf("[BuildMerkleProofs] node error, node is neither left node nor right node.")
				log.Println(errInfo)
				return nil, nil, errors.New(errInfo)
			}
			node = node.Parent
		}
	}
	return proofs, proofHelpers, nil
}

func (t *Tree) Update(index int64, nVal []byte) (err error) {
	if index >= 1<<t.MaxHeight {
		log.Println("[Update] invalid index")
		return errors.New("[Update] invalid index")
	}
	if index <= int64(len(t.Leaves)) {
		return t.updateExistOrNext(index, nVal)
	} else {
		for i := int64(len(t.Leaves)); i < index; i++ {
			err = t.updateExistOrNext(i, t.NilHashValueConst[0])
			if err != nil {
				log.Println("[Update] unable to update exist or next:", err)
				return err
			}
		}
		err = t.updateExistOrNext(index, nVal)
		if err != nil {
			log.Println("[Update] unable to update exist or next:", err)
			return err
		}
	}
	return nil
}

func (t *Tree) updateExistOrNext(index int64, nVal []byte) (err error) {
	if index >= 1<<t.MaxHeight {
		log.Println("[updateExistOrNext] invalid index")
		return errors.New("[updateExistOrNext] invalid index")
	}
	// empty tree
	if len(t.Leaves) == 0 {
		if index != 0 {
			log.Println("[updateExistOrNext] invalid index")
			return errors.New("[updateExistOrNext] invalid index")
		}
		nodeInfo := &Node{
			Value:  nVal,
			Height: 0,
		}
		t.Leaves = append(t.Leaves, nodeInfo)
		err = t.BuildTree(t.Leaves)
		return err
	}
	// index belong to leaves
	if index < int64(len(t.Leaves)) {
		node := t.Leaves[index]
		node.Value = nVal
		node = node.Parent
		for node != nil {
			if node.Right != nil {
				node.Value = t.HashSubTrees(node.Left.Value, node.Right.Value)
			} else {
				node.Value = t.HashSubTrees(node.Left.Value, t.NilHashValueConst[node.Left.Height])
			}
			node = node.Parent
		}
	} else { // index larger than leaves
		// that's also insert
		if index != int64(len(t.Leaves)) {
			return errors.New("[updateExistOrNext] the index should only be lastIndex+1")
		}
		// get last index
		lastIndex := len(t.Leaves) - 1
		// get last leave node
		node := t.Leaves[lastIndex]
		// even
		if (index+1)%2 == 0 {
			// construct node
			nNode := &Node{
				Value:  nVal,
				Parent: node.Parent,
				Height: 0,
			}
			node.Parent.Right = nNode
			t.Leaves = append(t.Leaves, nNode)
			node = node.Parent
			for node != nil {
				if node.Right != nil {
					node.Value = t.HashSubTrees(node.Left.Value, node.Right.Value)
				} else {
					node.Value = t.HashSubTrees(node.Left.Value, t.NilHashValueConst[node.Left.Height])
				}
				node = node.Parent
			}
		} else { // odd
			node = node.Parent.Parent
			nNode := &Node{
				Value:  nVal,
				Parent: nil,
				Height: 0,
			}
			parentNode := &Node{
				Value:  t.HashSubTrees(nVal, t.NilHashValueConst[0]),
				Left:   nNode,
				Parent: node,
				Height: nNode.Height + 1,
			}
			nNode.Parent = parentNode
			node.Right = parentNode
			t.Leaves = append(t.Leaves, nNode)
			for node != nil {
				if node.Right != nil {
					node.Value = t.HashSubTrees(node.Left.Value, node.Right.Value)
				} else {
					node.Value = t.HashSubTrees(node.Left.Value, t.NilHashValueConst[node.Left.Height])
				}
				node = node.Parent
			}
		}
	}
	return nil
}

func (t *Tree) insert(nodes []*Node) {

	if len(nodes) == 0 {
		log.Println("[BuildTree] smt BuildTree error, nodes length == 0")
		return
	} else {
		if nodes[0].Height == 0 && len(nodes) == 1 {
			t.RootNode = nodes[0]
			return
		}
	}
	var parents []*Node

	for i := 0; i < len(nodes); i += 2 {
		if nodes[i].Parent == nil {
			logInfo := fmt.Sprintf("[insert] boundary one: len(nodes) = %v. i = %v.", len(nodes), i)
			log.Println(logInfo)
			// The left node has no parent, need to create a parent node
			nodes[i].Parent = &Node{
				Value:  t.HashSubTrees(nodes[i].Value, t.NilHashValueConst[nodes[i].Height]),
				Left:   nodes[i],
				Right:  nil,
				Parent: nil,
				Height: nodes[i].Height - 1,
			}
		} else if i+1 <= len(nodes)-1 {
			if nodes[i+1].Parent == nil && nodes[i].Parent != nil {
				logInfo := fmt.Sprintf("[insert] boundary two:len(nodes) = %v. i = %v.", len(nodes), i)
				log.Println(logInfo)
				// The right node has no parent, but the left node has a parent, do not need to create a parent node
				nodes[i+1].Parent = nodes[i].Parent
				nodes[i+1].Parent.Right = nodes[i+1]
				nodes[i+1].Parent.Value = t.HashSubTrees(nodes[i].Value, nodes[i+1].Value)
			}
		}

		parents = append(parents, nodes[i].Parent)
	}
	t.insert(parents)
}

/*
	VerifyMerkleProofs: verify merkle proofs
	@inclusionProofs: inclusion proofs
	@helperProofs: helper function
*/
func (t *Tree) VerifyMerkleProofs(inclusionProofs [][]byte, helperProofs []int) bool {
	if len(inclusionProofs) != len(helperProofs)+1 {
		return false
	}
	// empty tree
	if len(t.Leaves) == 0 {
		return true
	}
	root := t.RootNode.Value
	node := inclusionProofs[0]
	for i := 1; i < len(inclusionProofs); i++ {
		switch helperProofs[i-1] {
		case Left:
			node = t.HashSubTrees(node, inclusionProofs[i])
			continue
		case Right:
			node = t.HashSubTrees(inclusionProofs[i], node)
			continue
		default:
			return false
		}
	}
	return bytes.Equal(root, node)
}

func (t *Tree) IsEmptyTree() bool {
	return len(t.Leaves) == 0
}
