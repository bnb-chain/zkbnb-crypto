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
	"testing"
)

func TestVerifyBlock(t *testing.T) {
	assert := groth16.NewAssert(t)

	var circuit, witness BlockConstraints
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("constraints:", r1cs.GetNbConstraints())
	tx := PrepareBlockSmall()
	witness, err = SetBlockWitness(tx)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(r1cs, &witness)
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
