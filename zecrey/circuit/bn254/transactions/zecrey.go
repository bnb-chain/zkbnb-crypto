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
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

type TransactionConstraints struct {
	// deposit tx
	DepositTransaction DepositTxConstraints
	// transfer tx
	TransferTransaction TransferTxConstraints
	// swap tx
	SwapTransaction SwapTxConstraints
	// withdraw tx
	WithdrawTransaction WithdrawTxConstraints
}

type Transaction struct {
	// deposit tx
	DepositTransaction *DepositTx
	// transfer tx
	TransferTransaction *TransferTx
	// swap tx
	SwapTransaction *SwapTx
	// withdraw tx
	WithdrawTransaction *WithdrawTx
}

type BlockConstraints struct {
	// public inputs
	OldRoot Variable `gnark:",public"`
	NewRoot Variable `gnark:",public"`
	// tx types
	TxsType [NbTxs]Variable
	// transactions
	Transactions [NbTxs]TransactionConstraints
	// account change for each transaction
	OldAccountRoots [NbTxs]Variable
	NewAccountRoots [NbTxs]Variable
}

func (circuit *BlockConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	// mimc
	hFunc, err := mimc.NewMiMC("ZecreyMIMCSeed", curveID)

	VerifyBlock(cs, *circuit, curveID, params, hFunc)

	return nil
}

func VerifyBlock(cs *ConstraintSystem, block BlockConstraints, curveID ecc.ID, params twistededwards.EdCurve, hFunc MiMC) {
	// check merkle roots
	cs.AssertIsEqual(block.OldRoot, block.OldAccountRoots[0])
	cs.AssertIsEqual(block.NewRoot, block.NewAccountRoots[NbTxs-1])
	for i := 1; i < NbTxs; i++ {
		cs.AssertIsEqual(block.OldAccountRoots[i], block.NewAccountRoots[i-1])
	}
	for i := 0; i < NbTxs; i++ {
		// set transaction type
		block.Transactions[i].DepositTransaction.IsEnabled = cs.IsZero(cs.Sub(block.TxsType[i], cs.Constant(DepositTxType)), curveID)
		block.Transactions[i].TransferTransaction.IsEnabled = cs.IsZero(cs.Sub(block.TxsType[i], cs.Constant(TransferTxType)), curveID)
		block.Transactions[i].SwapTransaction.IsEnabled = cs.IsZero(cs.Sub(block.TxsType[i], cs.Constant(SwapTxType)), curveID)
		block.Transactions[i].WithdrawTransaction.IsEnabled = cs.IsZero(cs.Sub(block.TxsType[i], cs.Constant(WithdrawTxType)), curveID)

		// set transaction old root and new root
		block.Transactions[i].DepositTransaction.OldAccountRoot = block.OldAccountRoots[i]
		block.Transactions[i].DepositTransaction.NewAccountRoot = block.NewAccountRoots[i]

		block.Transactions[i].TransferTransaction.OldAccountRoot = block.OldAccountRoots[i]
		block.Transactions[i].TransferTransaction.NewAccountRoot = block.NewAccountRoots[i]

		block.Transactions[i].SwapTransaction.OldAccountRoot = block.OldAccountRoots[i]
		block.Transactions[i].SwapTransaction.NewAccountRoot = block.NewAccountRoots[i]

		block.Transactions[i].WithdrawTransaction.OldAccountRoot = block.OldAccountRoots[i]
		block.Transactions[i].WithdrawTransaction.NewAccountRoot = block.NewAccountRoots[i]

		// verify transaction
		VerifyDepositTx(cs, block.Transactions[i].DepositTransaction, params, hFunc)
		VerifyTransferTx(cs, block.Transactions[i].TransferTransaction, params, hFunc)
		VerifySwapTx(cs, block.Transactions[i].SwapTransaction, params, hFunc)
		VerifyWithdrawTx(cs, block.Transactions[i].WithdrawTransaction, params, hFunc)
	}

}

type Block struct {
	// public inputs
	OldRoot []byte
	NewRoot []byte
	// tx types
	TxsType [NbTxs]int
	// transactions
	Transactions [NbTxs]*Transaction
	// account change for each transaction
	OldAccountRoots [NbTxs][]byte
	NewAccountRoots [NbTxs][]byte
}

func SetTransactionWitness(tx *Transaction) (witness TransactionConstraints, err error) {
	witness.DepositTransaction, err = SetDepositTxWitness(tx.DepositTransaction)
	if err != nil {
		return witness, err
	}
	witness.TransferTransaction, err = SetTransferTxWitness(tx.TransferTransaction)
	if err != nil {
		return witness, err
	}
	witness.SwapTransaction, err = SetSwapTxWitness(tx.SwapTransaction)
	if err != nil {
		return witness, err
	}
	witness.WithdrawTransaction, err = SetWithdrawTxWitness(tx.WithdrawTransaction)
	if err != nil {
		return witness, err
	}
	return witness, nil
}

func SetBlockWitness(block *Block) (witness BlockConstraints, err error) {
	// roots
	witness.OldRoot.Assign(block.OldRoot)
	witness.NewRoot.Assign(block.NewRoot)
	for i := 0; i < NbTxs; i++ {
		witness.TxsType[i].Assign(block.TxsType[i])
		witness.Transactions[i], err = SetTransactionWitness(block.Transactions[i])
		if err != nil {
			return witness, err
		}
		witness.OldAccountRoots[i].Assign(block.OldAccountRoots[i])
		witness.NewAccountRoots[i].Assign(block.NewAccountRoots[i])
	}
	return witness, nil
}
