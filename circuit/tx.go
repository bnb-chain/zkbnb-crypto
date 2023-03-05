/*
 * Copyright © 2022 ZkBNB Protocol
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

package circuit

import (
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

type Tx struct {
	// tx type
	TxType uint8
	// different transactions
	ChangePubKeyTxInfo     *ChangePubKeyTx
	DepositTxInfo          *DepositTx
	DepositNftTxInfo       *DepositNftTx
	TransferTxInfo         *TransferTx
	CreateCollectionTxInfo *CreateCollectionTx
	MintNftTxInfo          *MintNftTx
	TransferNftTxInfo      *TransferNftTx
	AtomicMatchTxInfo      *AtomicMatchTx
	CancelOfferTxInfo      *CancelOfferTx
	WithdrawTxInfo         *WithdrawTx
	WithdrawNftTxInfo      *WithdrawNftTx
	FullExitTxInfo         *FullExitTx
	FullExitNftTxInfo      *FullExitNftTx
	// nonce
	Nonce int64
	// expired at
	ExpiredAt int64
	// signature
	Signature *Signature
	// account root before
	AccountRootBefore []byte
	// account before info
	AccountsInfoBefore [NbAccountsPerTx]*types.Account
	// nft root before
	NftRootBefore []byte
	// nft before
	NftBefore *types.Nft
	// state root before
	StateRootBefore []byte
	// before account asset merkle proof
	MerkleProofsAccountAssetsBefore [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels][]byte
	// before account merkle proof
	MerkleProofsAccountBefore [NbAccountsPerTx][AccountMerkleLevels][]byte
	// before nft tree merkle proof
	MerkleProofsNftBefore [NftMerkleLevels][]byte
	// state root after
	StateRootAfter []byte
}
