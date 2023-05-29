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

package desert

import (
	"github.com/bnb-chain/zkbnb-crypto/circuit"
	desertTypes "github.com/bnb-chain/zkbnb-crypto/circuit/desert/types"
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

type Tx struct {
	// tx type
	TxType uint8

	ExitTxInfo    *ExitTx
	ExitNftTxInfo *ExitNftTx

	// account root
	AccountRoot []byte
	// account info
	AccountsInfo [NbAccountsPerTx]*desertTypes.Account
	// nft root
	NftRoot []byte
	// nft
	Nft *types.Nft
	// account asset merkle proof
	MerkleProofsAccountAssets [NbAccountsPerTx][circuit.AssetMerkleLevels][]byte
	// account merkle proof
	MerkleProofsAccounts [NbAccountsPerTx][circuit.AccountMerkleLevels][]byte
	// nft tree merkle proof
	MerkleProofsNft [circuit.NftMerkleLevels][]byte
}
