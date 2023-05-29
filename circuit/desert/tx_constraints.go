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
	"errors"
	"github.com/bnb-chain/zkbnb-crypto/circuit"
	desertTypes "github.com/bnb-chain/zkbnb-crypto/circuit/desert/types"
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
	"log"
)

type TxConstraints struct {
	// tx type
	TxType types.Variable

	ExitTxInfo    ExitTxConstraints
	ExitNftTxInfo ExitNftTxConstraints

	// account root
	AccountRoot types.Variable
	// account
	AccountsInfo [NbAccountsPerTx]desertTypes.AccountConstraints
	// nft root
	NftRoot types.Variable
	// nft
	Nft types.NftConstraints
	// account asset merkle proof
	MerkleProofsAccountAssets [NbAccountsPerTx][circuit.AssetMerkleLevels]types.Variable
	// nft tree merkle proof
	MerkleProofsNft [circuit.NftMerkleLevels]types.Variable
	// account merkle proof
	MerkleProofsAccounts [NbAccountsPerTx][circuit.AccountMerkleLevels]types.Variable
}

func SetTxWitness(oTx *Tx) (witness TxConstraints, err error) {
	witness.TxType = int64(oTx.TxType)
	witness.ExitTxInfo = desertTypes.EmptyExitTxWitness()
	witness.ExitNftTxInfo = desertTypes.EmptyExitNftTxWitness()
	switch oTx.TxType {
	case desertTypes.TxTypeEmptyTx:
		break
	case desertTypes.TxTypeExit:
		witness.ExitTxInfo = desertTypes.SetExitTxWitness(oTx.ExitTxInfo)
		break
	case desertTypes.TxTypeExitNft:
		witness.ExitNftTxInfo = desertTypes.SetExitNftTxWitness(oTx.ExitNftTxInfo)
		break
	default:
		log.Println("[SetTxWitness] invalid oTx type")
		return witness, errors.New("[SetTxWitness] invalid oTx type")
	}
	// set common account & merkle parts
	// account root
	witness.AccountRoot = oTx.AccountRoot
	witness.NftRoot = oTx.NftRoot

	witness.Nft, err = types.SetNftWitness(oTx.Nft)
	if err != nil {
		log.Println("[SetTxWitness] unable to set nft witness:", err.Error())
		return witness, err
	}

	// account info, size is 2
	for i := 0; i < NbAccountsPerTx; i++ {
		// accounts info
		witness.AccountsInfo[i], err = desertTypes.SetAccountWitness(oTx.AccountsInfo[i])
		if err != nil {
			log.Println("[SetTxWitness] err info:", err)
			return witness, err
		}
		for k := 0; k < circuit.AssetMerkleLevels; k++ {
			// account assets
			witness.MerkleProofsAccountAssets[i][k] = oTx.MerkleProofsAccountAssets[i][k]
		}
		for j := 0; j < circuit.AccountMerkleLevels; j++ {
			// account
			witness.MerkleProofsAccounts[i][j] = oTx.MerkleProofsAccounts[i][j]
		}
	}

	for i := 0; i < circuit.NftMerkleLevels; i++ {
		// nft assets
		witness.MerkleProofsNft[i] = oTx.MerkleProofsNft[i]
	}
	return witness, nil
}
