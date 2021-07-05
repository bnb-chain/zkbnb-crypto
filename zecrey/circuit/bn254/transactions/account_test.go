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

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

func TestSerialize(t *testing.T) {
	tokenId := uint32(1)
	_, pk := twistedElgamal.GenKeyPair()
	b := big.NewInt(10)
	r := curve.RandomValue()
	balance, _ := twistedElgamal.Enc(b, r, pk)
	fmt.Println(balance.String())
	acc := &Account{
		Index:   0,
		TokenId: tokenId,
		Balance: balance,
		PubKey:  pk,
	}
	res := SerializeAccount(acc)
	accCopy := DeserializeAccount(res)
	fmt.Println(accCopy.Balance.String())
}

func TestMerkleProof(t *testing.T) {
	accounts, _, hashState := mockAccountTree(4)
	var buf bytes.Buffer
	buf.Write(hashState)
	h := zmimc.Hmimc
	h.Reset()
	merkleRootBefore, proofInclusionWithdrawBefore, numLeaves, err := merkletree.BuildReaderProof(&buf, h, h.Size(), 0)
	if err != nil {
		panic(err)
	}
	fmt.Println(new(big.Int).SetBytes(merkleRootBefore).String())
	fmt.Println(len(proofInclusionWithdrawBefore))
	helper := merkle.GenerateProofHelper(proofInclusionWithdrawBefore, 0, numLeaves)
	fmt.Println(len(helper))
	proof := merkletree.VerifyProof(h, merkleRootBefore, proofInclusionWithdrawBefore, 0, numLeaves)
	fmt.Println(proof)
	CRStar := curve.ScalarMul(curve.H, big.NewInt(-1))
	// update balance
	newBalance := &zecrey.ElGamalEnc{
		CL: accounts[0].Balance.CL,
		CR: curve.Add(accounts[0].Balance.CR, CRStar),
	}
	// accountBeforeWithdraw after deposit
	var accountAfterWithdraw Account
	accountAfterWithdraw = *accounts[0]
	accountAfterWithdraw.Balance = newBalance
	accounts, hashState = mockUpdateAccount(accounts, hashState, 0, &accountAfterWithdraw)
	buf.Reset()
	buf.Write(hashState)
	merkleRootAfter, proofInclusionWithdrawAfter, numLeaves, err := merkletree.BuildReaderProof(&buf, h, h.Size(), 0)
	if err != nil {
		panic(err)
	}
	proof = merkletree.VerifyProof(h, merkleRootAfter, proofInclusionWithdrawAfter, 0, numLeaves)
	fmt.Println(proof)
}
