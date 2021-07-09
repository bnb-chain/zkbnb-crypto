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
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

const (
	fakeIndex     = 0
	fakeIsEnabled = false
	fakeTokenId   = 0
)

var (
	fakeBytes  = []byte{0}
	fakePoint  = curve.ZeroPoint()
	fakeAmount = big.NewInt(0)
	fakeEnc    = &zecrey.ElGamalEnc{
		CL: fakePoint,
		CR: fakePoint,
	}
	fakeAccount = &Account{
		Index:   fakeIndex,
		TokenId: fakeTokenId,
		Balance: fakeEnc,
		PubKey:  fakePoint,
	}
	fakeMerkleProofs               = [AccountMerkleLevels][]byte{}
	fakeWithdrawMerkleProofs       = [NbWithdrawCountAndFee][AccountMerkleLevels][]byte{}
	fakeTransferMerkleProofs       = [NbTransferCountAndFee][AccountMerkleLevels][]byte{}
	fakeSwapMerkleProofs           = [NbSwapCountAndFee][AccountMerkleLevels][]byte{}
	fakeHelperMerkleProofs         = [AccountMerkleLevels - 1]int{}
	fakeWithdrawHelperMerkleProofs = [NbWithdrawCountAndFee][AccountMerkleLevels - 1]int{}
	fakeTransferHelperMerkleProofs = [NbTransferCountAndFee][AccountMerkleLevels - 1]int{}
	fakeSwapHelperMerkleProofs     = [NbSwapCountAndFee][AccountMerkleLevels - 1]int{}
)

func init() {
	for j := 0; j < NbWithdrawCountAndFee; j++ {
		for i := 0; i < AccountMerkleLevels; i++ {
			fakeWithdrawMerkleProofs[j][i] = []byte{0}
			if i != AccountMerkleLevels-1 {
				fakeWithdrawHelperMerkleProofs[j][i] = 0
			}
		}
	}
	for i := 0; i < AccountMerkleLevels; i++ {
		fakeMerkleProofs[i] = []byte{0}
		if i != AccountMerkleLevels-1 {
			fakeHelperMerkleProofs[i] = 0
		}
	}
	for i := 0; i < NbTransferCountAndFee; i++ {
		for j := 0; j < AccountMerkleLevels; j++ {
			fakeTransferMerkleProofs[i][j] = []byte{0}
			if j != AccountMerkleLevels-1 {
				fakeTransferHelperMerkleProofs[i][j] = 0
				if i < NbSwapCount {
					fakeSwapHelperMerkleProofs[i][j] = 0
				}
			}
			if i < NbSwapCount {
				fakeSwapMerkleProofs[i][j] = []byte{0}
			}
		}
	}
}

func FakeDepositTx() *DepositTx {
	return &DepositTx{
		IsEnabled: fakeIsEnabled,
		// token id
		TokenId: fakeTokenId,
		// Public key
		PublicKey: fakePoint,
		// deposit amount
		Amount: fakeAmount,
		// old Account Info
		AccountBefore: fakeAccount,
		// new Account Info
		AccountAfter: fakeAccount,
		// generator
		H: fakePoint,

		// before deposit merkle proof
		AccountMerkleProofsBefore:       fakeMerkleProofs,
		AccountHelperMerkleProofsBefore: fakeHelperMerkleProofs,

		// after deposit merkle proof
		AccountMerkleProofsAfter:       fakeMerkleProofs,
		AccountHelperMerkleProofsAfter: fakeHelperMerkleProofs,

		// old account root
		OldAccountRoot: fakeBytes,
		// new account root
		NewAccountRoot: fakeBytes,
	}
}

func FakeWithdrawTx() *WithdrawTx {
	return &WithdrawTx{
		IsEnabled: fakeIsEnabled,
		// withdraw proof
		Proof: zecrey.FakeWithdrawProof(),
		// before withdraw merkle proof
		AccountMerkleProofsBefore:       fakeWithdrawMerkleProofs,
		AccountHelperMerkleProofsBefore: fakeWithdrawHelperMerkleProofs,

		// after withdraw merkle proof
		AccountMerkleProofsAfter:       fakeWithdrawMerkleProofs,
		AccountHelperMerkleProofsAfter: fakeWithdrawHelperMerkleProofs,

		// old Account Info
		AccountBefore: fakeAccount,
		// new Account Info
		AccountAfter: fakeAccount,

		// fee releated
		Fee:              fakeAmount,
		FeeAccountBefore: fakeAccount,
		FeeAccountAfter:  fakeAccount,

		// old account root
		OldAccountRoot: fakeBytes,
		// new account root
		NewAccountRoot: fakeBytes,
	}
}

func FakeTransferTx() *TransferTx {
	return &TransferTx{
		IsEnabled: fakeIsEnabled,
		// withdraw proof
		Proof: zecrey.FakeTransferProof(),
		// before transfer merkle proof
		AccountMerkleProofsBefore:       fakeTransferMerkleProofs,
		AccountHelperMerkleProofsBefore: fakeTransferHelperMerkleProofs,

		// after transfer merkle proof
		AccountMerkleProofsAfter:       fakeTransferMerkleProofs,
		AccountHelperMerkleProofsAfter: fakeTransferHelperMerkleProofs,

		// old Account Info
		AccountBefore: [NbTransferCount]*Account{fakeAccount, fakeAccount, fakeAccount},
		// new Account Info
		AccountAfter: [NbTransferCount]*Account{fakeAccount, fakeAccount, fakeAccount},

		// fee releated
		Fee:              fakeAmount,
		FeeAccountBefore: fakeAccount,
		FeeAccountAfter:  fakeAccount,

		// old account root
		OldAccountRoot: fakeBytes,
		// new account root
		NewAccountRoot: fakeBytes,
	}
}

func FakeSwapTx() *SwapTx {
	return &SwapTx{
		IsEnabled: fakeIsEnabled,
		// swap proof
		Proof: zecrey.FakeSwapProof(),
		// is first proof
		IsFirstProof: fakeIsEnabled,
		// before withdraw merkle proof
		AccountMerkleProofsBefore:       fakeSwapMerkleProofs,
		AccountHelperMerkleProofsBefore: fakeSwapHelperMerkleProofs,

		// after withdraw merkle proof
		AccountMerkleProofsAfter:       fakeSwapMerkleProofs,
		AccountHelperMerkleProofsAfter: fakeSwapHelperMerkleProofs,

		// old Account Info
		AccountBefore: [NbSwapCount]*Account{fakeAccount, fakeAccount},
		// new Account Info
		AccountAfter: [NbSwapCount]*Account{fakeAccount, fakeAccount},

		// fee releated
		Fee:              fakeAmount,
		FeeAccountBefore: fakeAccount,
		FeeAccountAfter:  fakeAccount,

		// old account root
		OldAccountRoot: fakeBytes,
		// new account root
		NewAccountRoot: fakeBytes,
	}
}
