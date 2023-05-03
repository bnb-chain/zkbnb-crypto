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

package types

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/consensys/gnark/std/hash/poseidon"
)

type ChangePubKeyTx struct {
	AccountIndex      int64
	L1Address         []byte
	PubKey            *eddsa.PublicKey
	Nonce             int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
}

type ChangePubKeyTxConstraints struct {
	AccountIndex      Variable
	L1Address         Variable
	PubKey            PublicKeyConstraints
	Nonce             Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyChangePubKeyTxWitness() (witness ChangePubKeyTxConstraints) {
	return ChangePubKeyTxConstraints{
		AccountIndex:      ZeroInt,
		L1Address:         ZeroInt,
		PubKey:            EmptyPublicKeyWitness(),
		Nonce:             ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func SetChangePubKeyTxWitness(tx *ChangePubKeyTx) (witness ChangePubKeyTxConstraints) {
	witness = ChangePubKeyTxConstraints{
		AccountIndex:      tx.AccountIndex,
		L1Address:         tx.L1Address,
		PubKey:            SetPubKeyWitness(tx.PubKey),
		Nonce:             tx.Nonce,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromChangePubKeyTx(api API, tx ChangePubKeyTxConstraints, nonce Variable, expiredAt Variable) (hashVal Variable) {
	return poseidon.Poseidon(api, ChainId, TxTypeChangePubKey, tx.AccountIndex, nonce, expiredAt, tx.GasFeeAssetId, tx.GasFeeAssetAmount,
		tx.L1Address, tx.PubKey.A.X, tx.PubKey.A.Y)
}

func VerifyChangePubKeyTx(
	api API, flag Variable,
	tx *ChangePubKeyTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	pubData = CollectPubDataFromChangePubKey(api, *tx)
	//CheckEmptyAccountNode(api, flag, accountsBefore[0])

	// verify params
	// account index
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	// l1 address
	IsVariableEqual(api, flag, tx.L1Address, accountsBefore[0].L1Address)
	// nonce
	IsVariableEqual(api, flag, tx.Nonce, accountsBefore[0].Nonce)
	// asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	// should have enough assets
	tx.GasFeeAssetAmount = UnpackAmount(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[0].Balance)

	return pubData
}
