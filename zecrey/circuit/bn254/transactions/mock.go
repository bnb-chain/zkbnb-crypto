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
	"math/big"
	"zecrey-crypto/accumulators/merkleTree"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/ffmath"
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

func mockTwoAccountTree(nbAccounts int) ([]*Account, []*Account, []*big.Int, []*big.Int, []*big.Int, []byte, []byte) {
	var (
		accountsT1  []*Account
		accountsT2  []*Account
		balancesT1  []*big.Int
		balancesT2  []*big.Int
		sks         []*big.Int
		hashStateT1 []byte
		hashStateT2 []byte
	)
	size := zmimc.Hmimc.Size()
	tokenId := uint32(1)
	accountsT1 = make([]*Account, nbAccounts)
	accountsT2 = make([]*Account, nbAccounts)
	balancesT1 = make([]*big.Int, nbAccounts)
	balancesT2 = make([]*big.Int, nbAccounts)
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
		balancesT1[i] = b
		balancesT2[i] = b
		copy(hashStateT1[i*size:(i+1)*size], accHashT1)
		copy(hashStateT2[i*size:(i+1)*size], accHashT2)
	}
	return accountsT1, accountsT2, sks, balancesT1, balancesT2, hashStateT1, hashStateT2
}

func MockAccountTree(nbAccounts int) ([]*Account, []*big.Int, []*big.Int, []byte) {
	var (
		accounts  []*Account
		sks       []*big.Int
		balances  []*big.Int
		hashState []byte
	)
	size := zmimc.Hmimc.Size()
	tokenId := uint32(1)
	accounts = make([]*Account, nbAccounts)
	sks = make([]*big.Int, nbAccounts)
	balances = make([]*big.Int, nbAccounts)
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
		balances[i] = b
		copy(hashState[i*size:(i+1)*size], accHash)
	}
	return accounts, sks, balances, hashState
}

func PrepareBlockSmall() *Block {
	var txsType [NbTxs]int
	var txs [NbTxs]*Transaction
	var oldRoot, newRoot []byte
	var oldAccountRoots, newAccountRoots [NbTxs][]byte
	// change NbTxs to 2
	// create accountsT1
	accountsT1, _, sks, balancesT1, _, hashStateT1, _ := mockTwoAccountTree(8)
	// mock deposit
	depositTx1, accountsT1, hashStateT1 := mockDeposit(hashStateT1, accountsT1, 1, 1)
	tx1 := mockDepositTransaction(depositTx1)
	txsType[0] = DepositTxType
	txs[0] = tx1
	oldRoot = depositTx1.OldAccountRoot
	oldAccountRoots[0] = depositTx1.OldAccountRoot
	newAccountRoots[0] = depositTx1.NewAccountRoot
	feePos := uint64(0)
	fee := big.NewInt(1)
	transferTx1, accountsT1, hashStateT1 := mockTransfer(hashStateT1, accountsT1, sks, balancesT1, [NbTransferCount]uint64{2, 3, 5}, [NbTransferCount]*big.Int{big.NewInt(-5), big.NewInt(1), big.NewInt(3)}, feePos, fee)
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

func mockNoopTransaction() *Transaction {
	return &Transaction{
		DepositTransaction:  FakeDepositTx(),
		TransferTransaction: FakeTransferTx(),
		SwapTransaction:     FakeSwapTx(),
		WithdrawTransaction: FakeWithdrawTx(),
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

func mockTransfer(hashState []byte, accounts []*Account, sks []*big.Int, balances []*big.Int, poses [NbTransferCount]uint64, bs [NbTransferCount]*big.Int, feePos uint64, fee *big.Int) (*TransferTx, []*Account, []byte) {
	accountBeforeTransfer1 := accounts[poses[0]]
	accountBeforeTransfer2 := accounts[poses[1]]
	accountBeforeTransfer3 := accounts[poses[2]]
	acc1 := [NbTransferCount]*Account{accountBeforeTransfer1, accountBeforeTransfer2, accountBeforeTransfer3}
	var acc2 [NbTransferCount]*Account
	sk1 := sks[poses[0]]
	tokenId := uint32(1)
	relation, err := zecrey.NewPTransferProofRelation(tokenId, fee)
	if err != nil {
		panic(err)
	}
	relation.AddStatement(accountBeforeTransfer1.Balance, accountBeforeTransfer1.PubKey, balances[poses[0]], bs[0], sk1)
	relation.AddStatement(accountBeforeTransfer2.Balance, accountBeforeTransfer2.PubKey, nil, bs[1], nil)
	relation.AddStatement(accountBeforeTransfer3.Balance, accountBeforeTransfer3.PubKey, nil, bs[2], nil)
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
	// fee related
	var feeAccountBefore, feeAccountAfter Account
	feeAccountBefore = *accounts[feePos]
	feeAccountAfter = *accounts[feePos]
	feeNewBalance := &zecrey.ElGamalEnc{
		CL: feeAccountAfter.Balance.CL,
		CR: curve.Add(feeAccountAfter.Balance.CR, curve.ScalarMul(curve.H, fee)),
	}
	feeAccountAfter.Balance = feeNewBalance

	// create deposit tx
	tx, accounts, hashState := mockTransferTx(true, proof, accounts, hashState, acc1, acc2, poses, &feeAccountBefore, &feeAccountAfter, feePos, fee)
	return tx, accounts, hashState
}

func mockSwap(hashStateT1 []byte, accountsT1 []*Account, balancesT1 []*big.Int, hashStateT2 []byte, balancesT2 []*big.Int, accountsT2 []*Account, sks []*big.Int, poses [NbSwapCount]uint64) (*SwapTx, *SwapTx, []*Account, []byte, []*Account, []byte) {
	// before swap first chain accounts
	accountBeforeSwap1 := accountsT1[poses[0]]
	accountBeforeSwap2 := accountsT1[poses[1]]
	accBeforeT1 := [NbSwapCount]*Account{accountBeforeSwap1, accountBeforeSwap2}
	// before swap second chain accounts
	feePos := uint64(0)
	fee := big.NewInt(1)
	// fee related
	var feeAccountBefore, feeAccountAfter Account
	feeAccountBefore = *accountsT1[feePos]
	feeAccountAfter = *accountsT1[feePos]
	feeNewBalance := &zecrey.ElGamalEnc{
		CL: feeAccountAfter.Balance.CL,
		CR: curve.Add(feeAccountAfter.Balance.CR, curve.ScalarMul(curve.H, fee)),
	}
	feeAccountAfter.Balance = feeNewBalance
	// inverse index
	accountBeforeSwap3 := accountsT2[poses[1]]
	accountBeforeSwap4 := accountsT2[poses[0]]
	accBeforeT2 := [NbSwapCount]*Account{accountBeforeSwap3, accountBeforeSwap4}
	// create swap proof
	swapProof := mockSwapProof(accountsT1, accountsT2, balancesT1, balancesT2, sks, poses, fee)
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
	txT1, accountsT1, hashStateT1 := mockSwapTx(true, true, swapProof, accountsT1, hashStateT1, accBeforeT1, accAfterT1, poses, fee, &feeAccountBefore, &feeAccountAfter, feePos)
	txT2, accountsT2, hashStateT2 := mockSwapTx(true, false, swapProof, accountsT2, hashStateT2, accBeforeT2, accAfterT2, inversePoses, fee, &feeAccountBefore, &feeAccountAfter, feePos)
	return txT1, txT2, accountsT1, hashStateT1, accountsT2, hashStateT2
}

func mockWithdraw(hashState []byte, accounts []*Account, sks []*big.Int, balances []*big.Int, pos, amount int, fee *big.Int, feePos uint64) (*WithdrawTx, []*Account, []byte) {
	accountBeforeWithdraw := accounts[pos]
	sk := sks[pos]
	// withdraw b
	receiveAddr := "0xb1c297bBb2DC33F3c68920F02e88d2746b2F456d"
	b := big.NewInt(int64(amount))
	relation, err := zecrey.NewWithdrawRelation(accountBeforeWithdraw.Balance, accountBeforeWithdraw.PubKey, balances[pos], ffmath.Neg(b), sk, accountBeforeWithdraw.TokenId, receiveAddr, fee)
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

	// fee related
	var feeAccountBefore, feeAccountAfter Account
	feeAccountBefore = *accounts[feePos]
	feeAccountAfter = *accounts[feePos]
	feeNewBalance := &zecrey.ElGamalEnc{
		CL: feeAccountAfter.Balance.CL,
		CR: curve.Add(feeAccountAfter.Balance.CR, curve.ScalarMul(curve.H, fee)),
	}
	feeAccountAfter.Balance = feeNewBalance

	// accountBeforeWithdraw after deposit
	var accountAfterWithdraw Account
	accountAfterWithdraw = *accountBeforeWithdraw
	accountAfterWithdraw.Balance = newBalance
	// create deposit tx
	tx, accounts, hashState := mockWithdrawTx(true, proof, accounts, hashState, accountBeforeWithdraw, &accountAfterWithdraw, uint64(pos), fee, &feeAccountBefore, &feeAccountAfter, feePos)
	return tx, accounts, hashState
}

func mockDepositTx(isEnabled bool, tokenId uint32, accounts []*Account, hashState []byte, pk *zecrey.Point, amount *big.Int, acc1, acc2 *Account, pos uint64) (*DepositTx, []*Account, []byte) {
	h := zmimc.Hmimc
	var state [][]byte
	for i := 0; i < len(hashState)/h.Size(); i++ {
		state = append(state, hashState[i*h.Size():(i+1)*h.Size()])
	}
	leaves := merkleTree.CreateLeaves(state)
	tree, err := merkleTree.NewTree(leaves, h)
	if err != nil {
		panic(err)
	}
	proofInclusionWithdrawBefore, merkleProofHelperWithdrawBefore, err := tree.BuildMerkleProofs(int64(pos))
	if err != nil {
		panic(err)
	}
	inclusionBefore := merkleTree.CopyMerkleProofs(proofInclusionWithdrawBefore)
	res := tree.VerifyMerkleProofs(proofInclusionWithdrawBefore, merkleProofHelperWithdrawBefore)
	if !res {
		panic("invalid proof 1")
	}
	oldRoot := tree.Root
	accounts, hashState = mockUpdateAccount(accounts, hashState, int(pos), acc2)
	newAccHash := mockAccountHash(acc2, zmimc.Hmimc)
	err = tree.UpdateNode(int64(pos), newAccHash)
	if err != nil {
		panic(err)
	}
	proofInclusionWithdrawAfter, merkleProofHelperWithdrawAfter, err := tree.BuildMerkleProofs(int64(pos))
	if err != nil {
		panic(err)
	}
	newRoot := tree.Root
	res = tree.VerifyMerkleProofs(proofInclusionWithdrawAfter, merkleProofHelperWithdrawAfter)
	if !res {
		panic("invalid proof 2")
	}
	tx := &DepositTx{
		IsEnabled: isEnabled,
		// token id
		TokenId: tokenId,
		// Public key
		PublicKey: pk,
		// deposit amount
		Amount: amount,
		// old Account Info
		AccountBefore: acc1,
		// new Account Info
		AccountAfter: acc2,
		// generator
		H: zecrey.H,

		// before deposit merkle proof
		AccountMerkleProofsBefore:       setFixedMerkleProofs(inclusionBefore),
		AccountHelperMerkleProofsBefore: setFixedMerkleProofsHelper(merkleProofHelperWithdrawBefore),

		// after deposit merkle proof
		AccountMerkleProofsAfter:       setFixedMerkleProofs(proofInclusionWithdrawAfter),
		AccountHelperMerkleProofsAfter: setFixedMerkleProofsHelper(merkleProofHelperWithdrawAfter),

		// old account root
		OldAccountRoot: oldRoot,
		// new account root
		NewAccountRoot: newRoot,
	}
	return tx, accounts, hashState
}

func mockSwapTx(isEnabled, isFirstProof bool, proof *zecrey.SwapProof, accounts []*Account, hashState []byte, acc1, acc2 [NbSwapCount]*Account, poses [NbSwapCount]uint64, fee *big.Int, feeAccountBefore, feeAccountAfter *Account, feePos uint64) (*SwapTx, []*Account, []byte) {
	tx := &SwapTx{
		IsEnabled:    isEnabled,
		IsFirstProof: isFirstProof,
		Proof:        proof,
	}
	// old merkle proofs
	h := zmimc.Hmimc
	var state [][]byte
	for i := 0; i < len(hashState)/h.Size(); i++ {
		state = append(state, hashState[i*h.Size():(i+1)*h.Size()])
	}
	leaves := merkleTree.CreateLeaves(state)
	tree, err := merkleTree.NewTree(leaves, h)
	if err != nil {
		panic(err)
	}
	// old merkle proof
	for i := 0; i < NbSwapCount; i++ {
		proofInclusionTransferBefore, merkleProofHelperTransferBefore, err := tree.BuildMerkleProofs(int64(poses[i]))
		if err != nil {
			panic(err)
		}
		tx.AccountMerkleProofsBefore[i] = setFixedMerkleProofs(proofInclusionTransferBefore)
		tx.AccountHelperMerkleProofsBefore[i] = setFixedMerkleProofsHelper(merkleProofHelperTransferBefore)
		tx.AccountBefore[i] = acc1[i]
		tx.AccountAfter[i] = acc2[i]
	}
	tx.OldAccountRoot = tree.Root
	proofInclusionTransferBefore, merkleProofHelperTransferBefore, err := tree.BuildMerkleProofs(int64(feePos))
	if err != nil {
		panic(err)
	}
	tx.AccountMerkleProofsBefore[NbSwapCount] = setFixedMerkleProofs(proofInclusionTransferBefore)
	tx.AccountHelperMerkleProofsBefore[NbSwapCount] = setFixedMerkleProofsHelper(merkleProofHelperTransferBefore)

	for i := 0; i < NbSwapCount; i++ {
		accounts, hashState = mockUpdateAccount(accounts, hashState, int(poses[i]), acc2[i])
		newAccHash := mockAccountHash(acc2[i], zmimc.Hmimc)
		err := tree.UpdateNode(int64(poses[i]), newAccHash)
		if err != nil {
			panic(err)
		}
	}
	accounts, hashState = mockUpdateAccount(accounts, hashState, int(feePos), feeAccountAfter)
	newAccHash := mockAccountHash(feeAccountAfter, zmimc.Hmimc)
	err = tree.UpdateNode(int64(feePos), newAccHash)
	if err != nil {
		panic(err)
	}
	for i := 0; i < NbSwapCount; i++ {
		// new merkle proofs
		proofInclusionTransferAfter, merkleProofHelperTransferAfter, err := tree.BuildMerkleProofs(int64(poses[i]))
		if err != nil {
			panic(err)
		}
		tx.AccountMerkleProofsAfter[i] = setFixedMerkleProofs(proofInclusionTransferAfter)
		tx.AccountHelperMerkleProofsAfter[i] = setFixedMerkleProofsHelper(merkleProofHelperTransferAfter)
	}
	tx.NewAccountRoot = tree.Root
	proofInclusionTransferAfter, merkleProofHelperTransferAfter, err := tree.BuildMerkleProofs(int64(feePos))
	if err != nil {
		panic(err)
	}
	tx.AccountMerkleProofsAfter[NbSwapCount] = setFixedMerkleProofs(proofInclusionTransferAfter)
	tx.AccountHelperMerkleProofsAfter[NbSwapCount] = setFixedMerkleProofsHelper(merkleProofHelperTransferAfter)

	tx.Fee = fee
	tx.FeeAccountBefore = feeAccountBefore
	tx.FeeAccountAfter = feeAccountAfter
	return tx, accounts, hashState
}

func mockTransferTx(isEnabled bool, proof *zecrey.PTransferProof, accounts []*Account, hashState []byte, acc1, acc2 [NbTransferCount]*Account, poses [NbTransferCount]uint64, feeAccountBefore, feeAccountAfter *Account, feePos uint64, fee *big.Int) (*TransferTx, []*Account, []byte) {
	tx := &TransferTx{
		IsEnabled: isEnabled,
		Proof:     proof,
	}
	// old merkle proofs
	h := zmimc.Hmimc
	var state [][]byte
	for i := 0; i < len(hashState)/h.Size(); i++ {
		state = append(state, hashState[i*h.Size():(i+1)*h.Size()])
	}
	leaves := merkleTree.CreateLeaves(state)
	tree, err := merkleTree.NewTree(leaves, h)
	if err != nil {
		panic(err)
	}
	// old merkle proof
	for i := 0; i < NbTransferCount; i++ {
		proofInclusionTransferBefore, merkleProofHelperTransferBefore, err := tree.BuildMerkleProofs(int64(poses[i]))
		if err != nil {
			panic(err)
		}
		tx.AccountMerkleProofsBefore[i] = setFixedMerkleProofs(proofInclusionTransferBefore)
		tx.AccountHelperMerkleProofsBefore[i] = setFixedMerkleProofsHelper(merkleProofHelperTransferBefore)
		tx.AccountBefore[i] = acc1[i]
		tx.AccountAfter[i] = acc2[i]
	}
	tx.OldAccountRoot = tree.Root
	// set fee account
	proofInclusionTransferBefore, merkleProofHelperTransferBefore, err := tree.BuildMerkleProofs(int64(feePos))
	if err != nil {
		panic(err)
	}
	tx.AccountMerkleProofsBefore[NbTransferCount] = setFixedMerkleProofs(proofInclusionTransferBefore)
	tx.AccountHelperMerkleProofsBefore[NbTransferCount] = setFixedMerkleProofsHelper(merkleProofHelperTransferBefore)
	tx.FeeAccountBefore = feeAccountBefore
	tx.FeeAccountAfter = feeAccountAfter

	for i := 0; i < NbTransferCount; i++ {
		accounts, hashState = mockUpdateAccount(accounts, hashState, int(poses[i]), acc2[i])
		newAccHash := mockAccountHash(acc2[i], zmimc.Hmimc)
		err := tree.UpdateNode(int64(poses[i]), newAccHash)
		if err != nil {
			panic(err)
		}
	}
	accounts, hashState = mockUpdateAccount(accounts, hashState, int(feePos), feeAccountAfter)
	newAccHash := mockAccountHash(feeAccountAfter, zmimc.Hmimc)
	err = tree.UpdateNode(int64(feePos), newAccHash)
	if err != nil {
		panic(err)
	}
	for i := 0; i < NbTransferCount; i++ {
		// new merkle proofs
		proofInclusionTransferAfter, merkleProofHelperTransferAfter, err := tree.BuildMerkleProofs(int64(poses[i]))
		if err != nil {
			panic(err)
		}
		tx.AccountMerkleProofsAfter[i] = setFixedMerkleProofs(proofInclusionTransferAfter)
		tx.AccountHelperMerkleProofsAfter[i] = setFixedMerkleProofsHelper(merkleProofHelperTransferAfter)
	}
	tx.NewAccountRoot = tree.Root
	proofInclusionTransferAfter, merkleProofHelperTransferAfter, err := tree.BuildMerkleProofs(int64(feePos))
	if err != nil {
		panic(err)
	}
	tx.AccountMerkleProofsAfter[NbTransferCount] = setFixedMerkleProofs(proofInclusionTransferAfter)
	tx.AccountHelperMerkleProofsAfter[NbTransferCount] = setFixedMerkleProofsHelper(merkleProofHelperTransferAfter)
	tx.Fee = fee
	return tx, accounts, hashState
}

func mockWithdrawTx(isEnabled bool, proof *zecrey.WithdrawProof, accounts []*Account, hashState []byte, acc1, acc2 *Account, pos uint64, fee *big.Int, feeAccountBefore, feeAccountAfter *Account, feePos uint64) (*WithdrawTx, []*Account, []byte) {
	// old merkle proofs
	h := zmimc.Hmimc
	var state [][]byte
	for i := 0; i < len(hashState)/h.Size(); i++ {
		state = append(state, hashState[i*h.Size():(i+1)*h.Size()])
	}
	leaves := merkleTree.CreateLeaves(state)
	tree, err := merkleTree.NewTree(leaves, h)
	if err != nil {
		panic(err)
	}
	proofInclusionWithdrawBefore, merkleProofHelperWithdrawBefore, err := tree.BuildMerkleProofs(int64(pos))
	if err != nil {
		panic(err)
	}
	feeProofInclusionWithdrawBefore, feeMerkleProofHelperWithdrawBefore, err := tree.BuildMerkleProofs(int64(feePos))
	if err != nil {
		panic(err)
	}
	oldRoot := tree.Root

	accInclusionBefore := merkleTree.CopyMerkleProofs(proofInclusionWithdrawBefore)
	feeInclusionBefore := merkleTree.CopyMerkleProofs(feeProofInclusionWithdrawBefore)

	accounts, hashState = mockUpdateAccount(accounts, hashState, int(pos), acc2)
	accounts, hashState = mockUpdateAccount(accounts, hashState, int(feePos), feeAccountAfter)
	newAccHash1 := mockAccountHash(acc2, zmimc.Hmimc)
	err = tree.UpdateNode(int64(pos), newAccHash1)
	if err != nil {
		panic(err)
	}
	newAccHash2 := mockAccountHash(feeAccountAfter, zmimc.Hmimc)
	err = tree.UpdateNode(int64(feePos), newAccHash2)
	if err != nil {
		panic(err)
	}
	// new merkle proofs
	proofInclusionWithdrawAfter, merkleProofHelperWithdrawAfter, err := tree.BuildMerkleProofs(int64(pos))
	if err != nil {
		panic(err)
	}
	feeProofInclusionWithdrawAfter, feeMerkleProofHelperWithdrawAfter, err := tree.BuildMerkleProofs(int64(feePos))
	if err != nil {
		panic(err)
	}
	newRoot := tree.Root

	tx := &WithdrawTx{
		IsEnabled: isEnabled,
		// withdraw proof
		Proof: proof,

		// old Account Info
		AccountBefore: acc1,
		// new Account Info
		AccountAfter: acc2,

		Fee:              fee,
		FeeAccountBefore: feeAccountBefore,
		FeeAccountAfter:  feeAccountAfter,

		// old account root
		OldAccountRoot: oldRoot,
		// new account root
		NewAccountRoot: newRoot,
	}
	tx.AccountMerkleProofsBefore[0] = setFixedMerkleProofs(accInclusionBefore)
	tx.AccountHelperMerkleProofsBefore[0] = setFixedMerkleProofsHelper(merkleProofHelperWithdrawBefore)
	tx.AccountMerkleProofsBefore[1] = setFixedMerkleProofs(feeInclusionBefore)
	tx.AccountHelperMerkleProofsBefore[1] = setFixedMerkleProofsHelper(feeMerkleProofHelperWithdrawBefore)

	tx.AccountMerkleProofsAfter[0] = setFixedMerkleProofs(proofInclusionWithdrawAfter)
	tx.AccountHelperMerkleProofsAfter[0] = setFixedMerkleProofsHelper(merkleProofHelperWithdrawAfter)
	tx.AccountMerkleProofsAfter[1] = setFixedMerkleProofs(feeProofInclusionWithdrawAfter)
	tx.AccountHelperMerkleProofsAfter[1] = setFixedMerkleProofsHelper(feeMerkleProofHelperWithdrawAfter)

	return tx, accounts, hashState
}

func mockSwapProof(accountsT1 []*Account, accountsT2 []*Account, sks []*big.Int, balancesT1 []*big.Int, balancesT2 []*big.Int, poses [NbSwapCount]uint64, fee *big.Int) *zecrey.SwapProof {
	// get accounts
	accT1A := accountsT1[poses[0]]
	accT2A := accountsT2[poses[0]]
	skA := sks[poses[0]]
	accT1B := accountsT1[poses[1]]
	accT2B := accountsT2[poses[1]]
	skB := sks[poses[1]]
	// from/to amount
	bStarFrom := big.NewInt(1)
	bStarTo := big.NewInt(8)
	// from/to tokenId
	fromTokenId := uint32(1)
	toTokenId := uint32(2)
	relationPart1, err := zecrey.NewSwapRelationPart1(accT1A.Balance, accT1B.Balance, accT1A.PubKey, accT1B.PubKey, balancesT1[poses[0]], bStarFrom, bStarTo, skA, fromTokenId, toTokenId, fee)
	if err != nil {
		panic(err)
	}
	swapProofPart1, err := zecrey.ProveSwapPart1(relationPart1, true)
	if err != nil {
		panic(err)
	}
	part1Res, err := swapProofPart1.Verify()
	if err != nil || !part1Res {
		panic(err)
	}
	relationPart2, err := zecrey.NewSwapRelationPart2(accT2B.Balance, accT2A.Balance, accT2B.PubKey, accT2A.PubKey, balancesT2[poses[1]], skB, fromTokenId, toTokenId, swapProofPart1)
	if err != nil {
		panic(err)
	}
	swapProof, err := zecrey.ProveSwapPart2(relationPart2, swapProofPart1)
	if err != nil {
		panic(err)
	}
	return swapProof
}
