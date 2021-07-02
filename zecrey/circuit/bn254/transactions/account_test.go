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

func mockUpdateAccount(accounts []*Account, hashState []byte, index int, newAccount *Account) ([]*Account, []byte) {
	size := zmimc.Hmimc.Size()
	accounts[index] = newAccount
	newAccHash := mockAccountHash(newAccount, zmimc.Hmimc)
	copy(hashState[index*size:(index+1)*size], newAccHash)
	return accounts, hashState
}

func mockTwoAccountTree(nbAccounts int) ([]*Account, []*Account, []*big.Int, []byte, []byte) {
	var (
		accountsT1  []*Account
		accountsT2  []*Account
		sks         []*big.Int
		hashStateT1 []byte
		hashStateT2 []byte
	)
	size := zmimc.Hmimc.Size()
	tokenId := uint32(1)
	accountsT1 = make([]*Account, nbAccounts)
	accountsT2 = make([]*Account, nbAccounts)
	sks = make([]*big.Int, nbAccounts)
	hashStateT1 = make([]byte, nbAccounts*size)
	hashStateT2 = make([]byte, nbAccounts*size)
	for i := 0; i < nbAccounts; i++ {
		sk, pk := twistedElgamal.GenKeyPair()
		b := big.NewInt(int64(i+1) * 10)
		rT1 := curve.RandomValue()
		rT2 := curve.RandomValue()
		balanceT1, _ := twistedElgamal.Enc(b, rT1, pk)
		balanceT2, _ := twistedElgamal.Enc(b, rT2, pk)
		accT1 := &Account{
			Index:   uint32(i),
			TokenId: tokenId,
			Balance: balanceT1,
			PubKey:  pk,
		}
		accT2 := &Account{
			Index:   uint32(i),
			TokenId: tokenId + 1,
			Balance: balanceT2,
			PubKey:  pk,
		}
		accHashT1 := mockAccountHash(accT1, zmimc.Hmimc)
		accHashT2 := mockAccountHash(accT2, zmimc.Hmimc)
		accountsT1[i] = accT1
		accountsT2[i] = accT2
		sks[i] = sk
		copy(hashStateT1[i*size:(i+1)*size], accHashT1)
		copy(hashStateT2[i*size:(i+1)*size], accHashT2)
	}
	return accountsT1, accountsT2, sks, hashStateT1, hashStateT2
}

func mockAccountTree(nbAccounts int) ([]*Account, []*big.Int, []byte) {
	var (
		accounts  []*Account
		sks       []*big.Int
		hashState []byte
	)
	size := zmimc.Hmimc.Size()
	tokenId := uint32(1)
	accounts = make([]*Account, nbAccounts)
	sks = make([]*big.Int, nbAccounts)
	hashState = make([]byte, nbAccounts*size)
	for i := 0; i < nbAccounts; i++ {
		sk, pk := twistedElgamal.GenKeyPair()
		b := big.NewInt(int64(i+1) * 10)
		r := curve.RandomValue()
		balance, _ := twistedElgamal.Enc(b, r, pk)
		acc := &Account{
			Index:   uint32(i),
			TokenId: tokenId,
			Balance: balance,
			PubKey:  pk,
		}
		accHash := mockAccountHash(acc, zmimc.Hmimc)
		accounts[i] = acc
		sks[i] = sk
		copy(hashState[i*size:(i+1)*size], accHash)
	}
	return accounts, sks, hashState
}

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
	res := serializeAccount(acc)
	accCopy := deserializeAccount(res)
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
