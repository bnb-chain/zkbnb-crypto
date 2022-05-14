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

package std

import "math/big"

type BuyNftTx struct {
	BuyerAccountIndex     int64
	OwnerAccountIndex     int64
	NftIndex              int64
	AssetId               int64
	AssetAmount           *big.Int
	TreasuryFeeRate       int64
	TreasuryFeeAmount     *big.Int
	TreasuryAccountIndex  int64
	CreatorTreasuryRate   int64
	CreatorTreasuryAmount *big.Int
	GasAccountIndex       int64
	GasFeeAssetId         int64
	GasFeeAssetAmount     *big.Int
}

type BuyNftTxConstraints struct {
	BuyerAccountIndex     Variable
	OwnerAccountIndex     Variable
	CreatorAccountIndex   Variable
	NftIndex              Variable
	AssetId               Variable
	AssetAmount           Variable
	TreasuryFeeRate       Variable
	TreasuryFeeAmount     Variable
	TreasuryAccountIndex  Variable
	CreatorTreasuryRate   Variable
	CreatorTreasuryAmount Variable
	GasAccountIndex       Variable
	GasFeeAssetId         Variable
	GasFeeAssetAmount     Variable
}

func EmptyBuyNftTxWitness() (witness BuyNftTxConstraints) {
	witness = BuyNftTxConstraints{
		BuyerAccountIndex:     ZeroInt,
		OwnerAccountIndex:     ZeroInt,
		CreatorAccountIndex:   ZeroInt,
		NftIndex:              ZeroInt,
		AssetId:               ZeroInt,
		AssetAmount:           ZeroInt,
		TreasuryFeeRate:       ZeroInt,
		TreasuryFeeAmount:     ZeroInt,
		TreasuryAccountIndex:  ZeroInt,
		CreatorTreasuryRate:   ZeroInt,
		CreatorTreasuryAmount: ZeroInt,
		GasAccountIndex:       ZeroInt,
		GasFeeAssetId:         ZeroInt,
		GasFeeAssetAmount:     ZeroInt,
	}
	return witness
}

func SetBuyNftTxWitness(tx *BuyNftTx) (witness BuyNftTxConstraints) {
	witness = BuyNftTxConstraints{
		BuyerAccountIndex:     tx.BuyerAccountIndex,
		OwnerAccountIndex:     tx.OwnerAccountIndex,
		CreatorAccountIndex:   tx.CreatorTreasuryRate,
		NftIndex:              tx.NftIndex,
		AssetId:               tx.AssetId,
		AssetAmount:           tx.AssetAmount,
		TreasuryFeeRate:       tx.TreasuryFeeRate,
		TreasuryFeeAmount:     tx.TreasuryFeeAmount,
		TreasuryAccountIndex:  tx.TreasuryAccountIndex,
		CreatorTreasuryRate:   tx.CreatorTreasuryRate,
		CreatorTreasuryAmount: tx.CreatorTreasuryAmount,
		GasAccountIndex:       tx.GasAccountIndex,
		GasFeeAssetId:         tx.GasFeeAssetId,
		GasFeeAssetAmount:     tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromBuyNftTx(tx BuyNftTxConstraints, nonce Variable, hFunc MiMC) (hashVal Variable) {
	hFunc.Reset()
	hFunc.Write(
		tx.OwnerAccountIndex,
		tx.NftIndex,
		tx.AssetId,
		tx.AssetAmount,
		tx.TreasuryAccountIndex,
		tx.TreasuryFeeRate,
		tx.CreatorTreasuryRate,
		tx.GasAccountIndex,
		tx.GasFeeAssetId,
		tx.GasFeeAssetAmount,
	)
	hFunc.Write(nonce)
	hashVal = hFunc.Sum()
	return hashVal
}

/*
	VerifyBuyNftTx:
	accounts order is:
	- BuyerAccount
		- Assets
			- AssetA
			- AssetGas
	- OwnerAccount
		- Assets
			- AssetA
	- TreasuryAccount
		- Assets
			- AssetA
	- CreatorAccount
		- Assets
			- AssetA
	- GasAccount
		- Assets
			- AssetGas
*/
func VerifyBuyNftTx(
	api API, flag Variable,
	tx *BuyNftTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints, nftBefore NftConstraints,
	hFunc *MiMC,
) {
	CollectPubDataFromBuyNft(api, flag, *tx, hFunc)
	// verify params
	// account index
	IsVariableEqual(api, flag, tx.BuyerAccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.OwnerAccountIndex, accountsBefore[1].AccountIndex)
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, accountsBefore[2].AccountIndex)
	IsVariableEqual(api, flag, tx.TreasuryAccountIndex, accountsBefore[3].AccountIndex)
	IsVariableEqual(api, flag, tx.GasAccountIndex, accountsBefore[4].AccountIndex)
	// asset id
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[0].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[1].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[3].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[0].AssetsInfo[1].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[4].AssetsInfo[0].AssetId)
	// nft info
	IsVariableEqual(api, flag, tx.CreatorAccountIndex, nftBefore.CreatorAccountIndex)
	IsVariableEqual(api, flag, tx.OwnerAccountIndex, nftBefore.OwnerAccountIndex)
	IsVariableEqual(api, flag, tx.AssetId, nftBefore.AssetId)
	IsVariableEqual(api, flag, tx.AssetAmount, nftBefore.AssetAmount)
	IsVariableEqual(api, flag, tx.CreatorTreasuryRate, nftBefore.CreatorTreasuryRate)
	// TODO treasury amount check
	// should have enough assets
	tx.AssetAmount = UnpackAmount(api, tx.AssetAmount)
	tx.TreasuryFeeAmount = UnpackFee(api, tx.TreasuryFeeAmount)
	tx.CreatorTreasuryAmount = UnpackFee(api, tx.CreatorTreasuryAmount)
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.AssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[0].AssetsInfo[1].Balance)
}
