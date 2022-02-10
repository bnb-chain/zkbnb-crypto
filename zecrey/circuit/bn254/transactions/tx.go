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

type Tx struct {
	// tx type
	TxType uint8
	// proof info
	DepositOrLockTxInfo      *DepositOrLockTx
	UnlockProofInfo          *UnlockProof
	TransferProofInfo        *TransferProof
	SwapProofInfo            *SwapProof
	AddLiquidityProofInfo    *AddLiquidityProof
	RemoveLiquidityProofInfo *RemoveLiquidityProof
	WithdrawProofInfo        *WithdrawProof
	// account root before
	AccountRootBefore []byte
	// account before info, size is 4
	AccountsInfoBefore [NbAccountsPerTx]*Account
	// before account asset merkle proof
	MerkleProofsAccountAssetsBefore       [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels][]byte
	MerkleProofsHelperAccountAssetsBefore [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleHelperLevels]int
	// before account asset lock merkle proof
	MerkleProofsAccountLockedAssetsBefore       [NbAccountsPerTx][LockedAssetMerkleLevels][]byte
	MerkleProofsHelperAccountLockedAssetsBefore [NbAccountsPerTx][LockedAssetMerkleHelperLevels]int
	// before account liquidity merkle proof
	MerkleProofsAccountLiquidityBefore       [NbAccountsPerTx][LiquidityMerkleLevels][]byte
	MerkleProofsHelperAccountLiquidityBefore [NbAccountsPerTx][LiquidityMerkleHelperLevels]int
	// before account merkle proof
	MerkleProofsAccountBefore       [NbAccountsPerTx][AccountMerkleLevels][]byte
	MerkleProofsHelperAccountBefore [NbAccountsPerTx][AccountMerkleHelperLevels]int
	// account root after
	AccountRootAfter []byte
	// account after info, size is 4
	AccountsInfoAfter [NbAccountsPerTx]*Account
	// after account asset merkle proof
	MerkleProofsAccountAssetsAfter       [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels][]byte
	MerkleProofsHelperAccountAssetsAfter [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleHelperLevels]int
	// after account asset lock merkle proof
	MerkleProofsAccountLockedAssetsAfter       [NbAccountsPerTx][LockedAssetMerkleLevels][]byte
	MerkleProofsHelperAccountLockedAssetsAfter [NbAccountsPerTx][LockedAssetMerkleHelperLevels]int
	// after account liquidity merkle proof
	MerkleProofsAccountLiquidityAfter       [NbAccountsPerTx][LiquidityMerkleLevels][]byte
	MerkleProofsHelperAccountLiquidityAfter [NbAccountsPerTx][LiquidityMerkleHelperLevels]int
	// after account merkle proof
	MerkleProofsAccountAfter       [NbAccountsPerTx][AccountMerkleLevels][]byte
	MerkleProofsHelperAccountAfter [NbAccountsPerTx][AccountMerkleHelperLevels]int
}
