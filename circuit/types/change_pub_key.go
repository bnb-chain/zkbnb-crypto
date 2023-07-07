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
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
}

type ChangePubKeyTxConstraints struct {
	AccountIndex      Variable
	L1Address         Variable
	PubKey            PublicKeyConstraints
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyChangePubKeyTxWitness() (witness ChangePubKeyTxConstraints) {
	return ChangePubKeyTxConstraints{
		AccountIndex:      ZeroInt,
		L1Address:         ZeroInt,
		PubKey:            EmptyPublicKeyWitness(),
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func SetChangePubKeyTxWitness(tx *ChangePubKeyTx) (witness ChangePubKeyTxConstraints) {
	witness = ChangePubKeyTxConstraints{
		AccountIndex:      tx.AccountIndex,
		L1Address:         tx.L1Address,
		PubKey:            SetPubKeyWitness(tx.PubKey),
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
	nonce Variable,
	tx *ChangePubKeyTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	// when the tx is not change pubkey tx, the nonce may be -1 when the tx is Layer1 tx.
	// and in the `CollectPubDataFromChangePubKey` function, nonce need to be in range [0, 2^32-1],
	// In order to make `CollectPubDataFromChangePubKey` works correctly, in this case we
	// just let nonce equal 0
	newNonce := api.Select(flag, nonce, 0)
	pubData = CollectPubDataFromChangePubKey(api, *tx, newNonce)

	// verify params
	// account index
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	// l1 address
	IsVariableEqual(api, flag, tx.L1Address, accountsBefore[0].L1Address)
	// asset id
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	// should have enough assets
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[0].Balance)

	return pubData
}

func VerifyDeltaChangePubKeyTx(api API, flag Variable, tx ChangePubKeyTxConstraints) {
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.AccountIndex), tx.AccountIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.L1Address), tx.L1Address)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.PubKey.A.X), tx.PubKey.A.X)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.PubKey.A.Y), tx.PubKey.A.Y)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.GasFeeAssetId), tx.GasFeeAssetId)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.GasFeeAssetAmount), tx.GasFeeAssetAmount)
}
