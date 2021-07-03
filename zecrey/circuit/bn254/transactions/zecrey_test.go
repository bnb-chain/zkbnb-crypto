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
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"testing"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

func TestVerifyBlock(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness BlockConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	tx := prepareBlockSmall()
	witness, err = SetBlockWitness(tx)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(r1cs, &witness)
}

func prepareBlockSmall() *Block {
	var txsType [NbTxs]int
	var txs [NbTxs]*Transaction
	var oldRoot, newRoot []byte
	var oldAccountRoots, newAccountRoots [NbTxs][]byte
	// change NbTxs to 2
	// create accountsT1
	accountsT1, _, sks, hashStateT1, _ := mockTwoAccountTree(8)
	// mock deposit
	depositTx1, accountsT1, hashStateT1 := mockDeposit(hashStateT1, accountsT1, 1, 1)
	tx1 := mockDepositTransaction(depositTx1)
	txsType[0] = DepositTxType
	txs[0] = tx1
	oldRoot = depositTx1.OldAccountRoot
	oldAccountRoots[0] = depositTx1.OldAccountRoot
	newAccountRoots[0] = depositTx1.NewAccountRoot
	transferTx1, accountsT1, hashStateT1 := mockTransfer(hashStateT1, accountsT1, sks, [NbTransferCount]uint64{2, 3, 5}, [NbTransferCount]*big.Int{big.NewInt(-4), big.NewInt(1), big.NewInt(3)})
	tx2 := mockTransferTransaction(transferTx1)
	txsType[1] = TransferTxType
	txs[1] = tx2
	newRoot = transferTx1.NewAccountRoot
	oldAccountRoots[1] = transferTx1.OldAccountRoot
	newAccountRoots[1] = transferTx1.NewAccountRoot
	return &Block{
		// public inputs
		OldRoot: oldRoot,
		NewRoot: newRoot,
		// tx types
		TxsType: txsType,
		// transactions
		Transactions: txs,
		// account change for each transaction
		OldAccountRoots: oldAccountRoots,
		NewAccountRoots: newAccountRoots,
	}
}

//func prepareBlock() *Block {
//	var txsType [NbTxs]int
//	var txs [NbTxs]*Transaction
//	var oldRoot, newRoot []byte
//	var oldAccountRoots, newAccountRoots [NbTxs][]byte
//	// change NbTxs to 7
//	// create accountsT1
//	accountsT1, accountsT2, sks, hashStateT1, hashStateT2 := mockTwoAccountTree(8)
//	// mock deposit
//	depositTx1, accountsT1, hashStateT1 := mockDeposit(hashStateT1, accountsT1, 1, 1)
//	tx1 := mockDepositTransaction(depositTx1)
//	txsType[0] = DepositTxType
//	txs[0] = tx1
//	oldRoot = depositTx1.OldAccountRoot
//	oldAccountRoots[0] = depositTx1.OldAccountRoot
//	newAccountRoots[0] = depositTx1.NewAccountRoot
//	depositTx2, accountsT1, hashStateT1 := mockDeposit(hashStateT1, accountsT1, 4, 5)
//	tx2 := mockDepositTransaction(depositTx2)
//	txsType[1] = DepositTxType
//	txs[1] = tx2
//	oldAccountRoots[1] = depositTx2.OldAccountRoot
//	newAccountRoots[1] = depositTx2.NewAccountRoot
//	// mock transfer
//	transferTx1, accountsT1, hashStateT1 := mockTransfer(hashStateT1, accountsT1, sks, [NbTransferCount]uint64{2, 3, 5}, [NbTransferCount]*big.Int{big.NewInt(-4), big.NewInt(1), big.NewInt(3)})
//	transferTx2, accountsT1, hashStateT1 := mockTransfer(hashStateT1, accountsT1, sks, [NbTransferCount]uint64{2, 3, 5}, [NbTransferCount]*big.Int{big.NewInt(-4), big.NewInt(1), big.NewInt(3)})
//	transferTx3, accountsT1, hashStateT1 := mockTransfer(hashStateT1, accountsT1, sks, [NbTransferCount]uint64{1, 2, 5}, [NbTransferCount]*big.Int{big.NewInt(-5), big.NewInt(2), big.NewInt(3)})
//	tx3 := mockTransferTransaction(transferTx1)
//	tx4 := mockTransferTransaction(transferTx2)
//	tx5 := mockTransferTransaction(transferTx3)
//	txsType[2] = TransferTxType
//	txsType[3] = TransferTxType
//	txsType[4] = TransferTxType
//	txs[2] = tx3
//	txs[3] = tx4
//	txs[4] = tx5
//	oldAccountRoots[2] = transferTx1.OldAccountRoot
//	newAccountRoots[2] = transferTx1.NewAccountRoot
//	oldAccountRoots[3] = transferTx2.OldAccountRoot
//	newAccountRoots[3] = transferTx2.NewAccountRoot
//	oldAccountRoots[4] = transferTx3.OldAccountRoot
//	newAccountRoots[4] = transferTx3.NewAccountRoot
//	// mock swap
//	swapTx1, _, accountsT1, hashStateT1, accountsT2, hashStateT2 := mockSwap(hashStateT1, accountsT1, hashStateT2, accountsT2, sks, [NbSwapCount]uint64{0, 3})
//	tx6 := mockSwapTransaction(swapTx1)
//	txsType[5] = SwapTxType
//	txs[5] = tx6
//	oldAccountRoots[5] = swapTx1.OldAccountRoot
//	newAccountRoots[5] = swapTx1.NewAccountRoot
//	// mock withdraw
//	withdrawTx, accountsT1, hashStateT1 := mockWithdraw(hashStateT1, accountsT1, sks, 4, 2)
//	tx7 := mockWithdrawTransaction(withdrawTx)
//	txsType[6] = WithdrawTxType
//	txs[6] = tx7
//	newRoot = withdrawTx.NewAccountRoot
//	oldAccountRoots[6] = withdrawTx.OldAccountRoot
//	newAccountRoots[6] = withdrawTx.NewAccountRoot
//	return &Block{
//		// public inputs
//		OldRoot: oldRoot,
//		NewRoot: newRoot,
//		// tx types
//		TxsType: txsType,
//		// transactions
//		Transactions: txs,
//		// account change for each transaction
//		OldAccountRoots: oldAccountRoots,
//		NewAccountRoots: newAccountRoots,
//	}
//}

func mockDepositTransaction(tx *DepositTx) *Transaction {
	return &Transaction{
		DepositTransaction:  tx,
		TransferTransaction: FakeTransferTx(),
		SwapTransaction:     FakeSwapTx(),
		WithdrawTransaction: FakeWithdrawTx(),
	}
}

func mockTransferTransaction(tx *TransferTx) *Transaction {
	return &Transaction{
		DepositTransaction:  FakeDepositTx(),
		TransferTransaction: tx,
		SwapTransaction:     FakeSwapTx(),
		WithdrawTransaction: FakeWithdrawTx(),
	}
}

func mockSwapTransaction(tx *SwapTx) *Transaction {
	return &Transaction{
		DepositTransaction:  FakeDepositTx(),
		TransferTransaction: FakeTransferTx(),
		SwapTransaction:     tx,
		WithdrawTransaction: FakeWithdrawTx(),
	}
}

func mockWithdrawTransaction(tx *WithdrawTx) *Transaction {
	return &Transaction{
		DepositTransaction:  FakeDepositTx(),
		TransferTransaction: FakeTransferTx(),
		SwapTransaction:     FakeSwapTx(),
		WithdrawTransaction: tx,
	}
}

func mockDeposit(hashState []byte, accounts []*Account, pos int, amount int) (*DepositTx, []*Account, []byte) {
	accountBeforeDeposit := accounts[pos]
	// deposit amount
	b := big.NewInt(int64(amount))
	// update balance
	CRDelta := curve.ScalarMul(curve.H, b)
	newBalance := &zecrey.ElGamalEnc{
		CL: accountBeforeDeposit.Balance.CL,
		CR: curve.Add(accountBeforeDeposit.Balance.CR, CRDelta),
	}
	// account after deposit
	var accountAfterDeposit Account
	accountAfterDeposit = *accountBeforeDeposit
	accountAfterDeposit.Balance = newBalance
	// create deposit tx
	tx, accounts, hashState := mockDepositTx(true, accountBeforeDeposit.TokenId, accounts, hashState, accountBeforeDeposit.PubKey, b, accountBeforeDeposit, &accountAfterDeposit, uint64(pos))
	return tx, accounts, hashState
}

func mockTransfer(hashState []byte, accounts []*Account, sks []*big.Int, poses [NbTransferCount]uint64, bs [NbTransferCount]*big.Int) (*TransferTx, []*Account, []byte) {
	accountBeforeTransfer1 := accounts[poses[0]]
	accountBeforeTransfer2 := accounts[poses[1]]
	accountBeforeTransfer3 := accounts[poses[2]]
	acc1 := [NbTransferCount]*Account{accountBeforeTransfer1, accountBeforeTransfer2, accountBeforeTransfer3}
	var acc2 [NbTransferCount]*Account
	sk1 := sks[poses[0]]
	tokenId := uint32(1)
	relation, err := zecrey.NewPTransferProofRelation(tokenId)
	if err != nil {
		panic(err)
	}
	relation.AddStatement(accountBeforeTransfer1.Balance, accountBeforeTransfer1.PubKey, bs[0], sk1)
	relation.AddStatement(accountBeforeTransfer2.Balance, accountBeforeTransfer2.PubKey, bs[1], nil)
	relation.AddStatement(accountBeforeTransfer3.Balance, accountBeforeTransfer3.PubKey, bs[2], nil)
	proof, err := zecrey.ProvePTransfer(relation)
	if err != nil {
		panic(err)
	}
	for i := 0; i < NbTransferCount; i++ {
		// update balance
		newBalance, err := twistedElgamal.EncAdd(accounts[poses[i]].Balance, relation.Statements[i].CDelta)
		if err != nil {
			panic(err)
		}
		// accountBeforeWithdraw after deposit
		var accountAfterTransfer Account
		accountAfterTransfer = *accounts[poses[i]]
		accountAfterTransfer.Balance = newBalance
		acc2[i] = &accountAfterTransfer
	}

	// create deposit tx
	tx, accounts, hashState := mockTransferTx(true, proof, accounts, hashState, acc1, acc2, poses)
	return tx, accounts, hashState
}

func mockSwap(hashStateT1 []byte, accountsT1 []*Account, hashStateT2 []byte, accountsT2 []*Account, sks []*big.Int, poses [NbSwapCount]uint64) (*SwapTx, *SwapTx, []*Account, []byte, []*Account, []byte) {
	// before swap first chain accounts
	accountBeforeSwap1 := accountsT1[poses[0]]
	accountBeforeSwap2 := accountsT1[poses[1]]
	accBeforeT1 := [NbSwapCount]*Account{accountBeforeSwap1, accountBeforeSwap2}
	// before swap second chain accounts
	// inverse index
	accountBeforeSwap3 := accountsT2[poses[1]]
	accountBeforeSwap4 := accountsT2[poses[0]]
	accBeforeT2 := [NbSwapCount]*Account{accountBeforeSwap3, accountBeforeSwap4}
	// create swap proof
	swapProof := mockSwapProof(accountsT1, accountsT2, sks, poses)
	// acc after swap
	var accountAfterSwap1, accountAfterSwap2, accountAfterSwap3, accountAfterSwap4 Account
	accountAfterSwap1 = *accountBeforeSwap1
	accountAfterSwap2 = *accountBeforeSwap2
	accountAfterSwap3 = *accountBeforeSwap3
	accountAfterSwap4 = *accountBeforeSwap4
	accountAfterSwap1.Balance, _ = twistedElgamal.EncAdd(accountAfterSwap1.Balance, swapProof.ProofPart1.CStar)
	accountAfterSwap2.Balance, _ = twistedElgamal.EncAdd(accountAfterSwap2.Balance, swapProof.ProofPart1.ReceiverCStar)
	accountAfterSwap3.Balance, _ = twistedElgamal.EncAdd(accountAfterSwap3.Balance, swapProof.ProofPart2.CStar)
	accountAfterSwap4.Balance, _ = twistedElgamal.EncAdd(accountAfterSwap4.Balance, swapProof.ProofPart2.ReceiverCStar)

	accAfterT1 := [NbSwapCount]*Account{&accountAfterSwap1, &accountAfterSwap2}
	accAfterT2 := [NbSwapCount]*Account{&accountAfterSwap3, &accountAfterSwap4}

	inversePoses := [NbSwapCount]uint64{poses[1], poses[0]}
	// create deposit tx
	txT1, accountsT1, hashStateT1 := mockSwapTx(true, true, swapProof, accountsT1, hashStateT1, accBeforeT1, accAfterT1, poses)
	txT2, accountsT2, hashStateT2 := mockSwapTx(true, false, swapProof, accountsT2, hashStateT2, accBeforeT2, accAfterT2, inversePoses)
	return txT1, txT2, accountsT1, hashStateT1, accountsT2, hashStateT2
}

func mockWithdraw(hashState []byte, accounts []*Account, sks []*big.Int, pos, amount int) (*WithdrawTx, []*Account, []byte) {
	accountBeforeWithdraw := accounts[pos]
	sk := sks[pos]
	// withdraw b
	receiveAddr := "0xb1c297bBb2DC33F3c68920F02e88d2746b2F456d"
	b := big.NewInt(int64(amount))
	relation, err := zecrey.NewWithdrawRelation(accountBeforeWithdraw.Balance, accountBeforeWithdraw.PubKey, ffmath.Neg(b), sk, accountBeforeWithdraw.TokenId, receiveAddr)
	if err != nil {
		panic(err)
	}
	proof, err := zecrey.ProveWithdraw(relation)
	if err != nil {
		panic(err)
	}
	// update balance
	newBalance := &zecrey.ElGamalEnc{
		CL: accountBeforeWithdraw.Balance.CL,
		CR: curve.Add(accountBeforeWithdraw.Balance.CR, relation.CRStar),
	}
	// accountBeforeWithdraw after deposit
	var accountAfterWithdraw Account
	accountAfterWithdraw = *accountBeforeWithdraw
	accountAfterWithdraw.Balance = newBalance
	// create deposit tx
	tx, accounts, hashState := mockWithdrawTx(true, proof, accounts, hashState, accountBeforeWithdraw, &accountAfterWithdraw, uint64(pos))
	return tx, accounts, hashState
}
