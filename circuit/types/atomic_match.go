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

import "github.com/consensys/gnark/std/hash/poseidon"

type AtomicMatchTx struct {
	AccountIndex      int64
	BuyOffer          *OfferTx
	SellOffer         *OfferTx
	CreatorAmount     int64
	TreasuryAmount    int64
	GasAccountIndex   int64
	GasFeeAssetId     int64
	GasFeeAssetAmount int64
}

type AtomicMatchTxConstraints struct {
	AccountIndex      Variable
	BuyOffer          OfferTxConstraints
	SellOffer         OfferTxConstraints
	CreatorAmount     Variable
	TreasuryAmount    Variable
	GasAccountIndex   Variable
	GasFeeAssetId     Variable
	GasFeeAssetAmount Variable
}

func EmptyAtomicMatchTxWitness() (witness AtomicMatchTxConstraints) {
	return AtomicMatchTxConstraints{
		AccountIndex:      ZeroInt,
		BuyOffer:          EmptyOfferTxWitness(),
		SellOffer:         EmptyOfferTxWitness(),
		CreatorAmount:     ZeroInt,
		TreasuryAmount:    ZeroInt,
		GasAccountIndex:   ZeroInt,
		GasFeeAssetId:     ZeroInt,
		GasFeeAssetAmount: ZeroInt,
	}
}

func ComputeHashFromOfferTx(api API, tx OfferTxConstraints) (hashVal Variable) {
	return poseidon.Poseidon(api,
		tx.Type, tx.OfferId, tx.AccountIndex, tx.NftIndex,
		tx.AssetId, tx.AssetAmount, tx.ListedAt, tx.ExpiredAt, tx.TreasuryRate,
	)
}

func SetAtomicMatchTxWitness(tx *AtomicMatchTx) (witness AtomicMatchTxConstraints) {
	witness = AtomicMatchTxConstraints{
		AccountIndex:      tx.AccountIndex,
		BuyOffer:          SetOfferTxWitness(tx.BuyOffer),
		SellOffer:         SetOfferTxWitness(tx.SellOffer),
		CreatorAmount:     tx.CreatorAmount,
		TreasuryAmount:    tx.TreasuryAmount,
		GasAccountIndex:   tx.GasAccountIndex,
		GasFeeAssetId:     tx.GasFeeAssetId,
		GasFeeAssetAmount: tx.GasFeeAssetAmount,
	}
	return witness
}

func ComputeHashFromAtomicMatchTx(api API, tx AtomicMatchTxConstraints, nonce Variable, expiredAt Variable) (hashVal Variable) {
	buyerOfferHash := poseidon.Poseidon(api,
		tx.BuyOffer.Type, tx.BuyOffer.OfferId, tx.BuyOffer.AccountIndex, tx.BuyOffer.NftIndex,
		tx.BuyOffer.AssetId, tx.BuyOffer.AssetAmount, tx.BuyOffer.ListedAt, tx.BuyOffer.ExpiredAt,
		tx.BuyOffer.Sig.R.X,
		tx.BuyOffer.Sig.R.Y,
		tx.BuyOffer.Sig.S,
	)
	sellerOfferHash := poseidon.Poseidon(api,
		tx.SellOffer.Type, tx.SellOffer.OfferId, tx.SellOffer.AccountIndex, tx.SellOffer.NftIndex,
		tx.SellOffer.AssetId, tx.SellOffer.AssetAmount, tx.SellOffer.ListedAt, tx.SellOffer.ExpiredAt,
		tx.SellOffer.Sig.R.X,
		tx.SellOffer.Sig.R.Y,
		tx.SellOffer.Sig.S,
	)
	return poseidon.Poseidon(api,
		ChainId, TxTypeAtomicMatch, tx.AccountIndex, nonce, expiredAt, tx.GasFeeAssetId, tx.GasFeeAssetAmount, buyerOfferHash, sellerOfferHash,
	)
}

func VerifyAtomicMatchTx(
	api API, flag Variable,
	tx *AtomicMatchTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
	nftBefore NftConstraints,
	blockCreatedAt Variable,
	hFunc MiMC,
) (pubData [PubDataBitsSizePerTx]Variable, err error) {
	fromAccount := 0
	buyAccount := 1
	sellAccount := 2
	creatorAccount := 3

	pubData = CollectPubDataFromAtomicMatch(api, *tx)
	// verify params
	IsVariableEqual(api, flag, tx.BuyOffer.Type, 0)
	IsVariableEqual(api, flag, tx.SellOffer.Type, 1)
	IsVariableEqual(api, flag, tx.BuyOffer.AssetId, tx.SellOffer.AssetId)
	IsVariableEqual(api, flag, tx.BuyOffer.AssetAmount, tx.SellOffer.AssetAmount)
	IsVariableEqual(api, flag, tx.BuyOffer.NftIndex, tx.SellOffer.NftIndex)
	IsVariableEqual(api, flag, tx.BuyOffer.AssetId, accountsBefore[buyAccount].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.SellOffer.AssetId, accountsBefore[sellAccount].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.SellOffer.AssetId, accountsBefore[creatorAccount].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[fromAccount].AssetsInfo[0].AssetId)
	IsVariableLessOrEqual(api, flag, blockCreatedAt, tx.BuyOffer.ExpiredAt)
	IsVariableLessOrEqual(api, flag, blockCreatedAt, tx.SellOffer.ExpiredAt)
	IsVariableEqual(api, flag, nftBefore.NftIndex, tx.SellOffer.NftIndex)
	IsVariableEqual(api, flag, tx.BuyOffer.TreasuryRate, tx.SellOffer.TreasuryRate)
	// verify signature
	hFunc.Reset()
	buyOfferHash := ComputeHashFromOfferTx(api, tx.BuyOffer)
	hFunc.Reset()
	notBuyer := api.IsZero(api.IsZero(api.Sub(tx.AccountIndex, tx.BuyOffer.AccountIndex)))
	notBuyer = api.And(flag, notBuyer)
	err = VerifyEddsaSig(notBuyer, api, hFunc, buyOfferHash, accountsBefore[1].AccountPk, tx.BuyOffer.Sig)
	if err != nil {
		return pubData, err
	}
	hFunc.Reset()
	sellOfferHash := ComputeHashFromOfferTx(api, tx.SellOffer)
	hFunc.Reset()
	notSeller := api.IsZero(api.IsZero(api.Sub(tx.AccountIndex, tx.SellOffer.AccountIndex)))
	notSeller = api.And(flag, notSeller)
	err = VerifyEddsaSig(notSeller, api, hFunc, sellOfferHash, accountsBefore[2].AccountPk, tx.SellOffer.Sig)
	if err != nil {
		return pubData, err
	}
	// verify account index
	// submitter
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[fromAccount].AccountIndex)
	// buyer
	IsVariableEqual(api, flag, tx.BuyOffer.AccountIndex, accountsBefore[buyAccount].AccountIndex)
	// seller
	IsVariableEqual(api, flag, tx.SellOffer.AccountIndex, accountsBefore[sellAccount].AccountIndex)
	// creator
	IsVariableEqual(api, flag, nftBefore.CreatorAccountIndex, accountsBefore[creatorAccount].AccountIndex)
	// verify buy offer id
	buyOfferIdBits := api.ToBinary(tx.BuyOffer.OfferId, 24)
	buyAssetId := api.FromBinary(buyOfferIdBits[7:]...)
	buyOfferIndex := api.Sub(tx.BuyOffer.OfferId, api.Mul(buyAssetId, OfferSizePerAsset))
	buyOfferIndexBits := api.ToBinary(accountsBefore[buyAccount].AssetsInfo[1].OfferCanceledOrFinalized, OfferSizePerAsset)
	for i := 0; i < OfferSizePerAsset; i++ {
		isZero := api.IsZero(api.Sub(buyOfferIndex, i))
		IsVariableEqual(api, isZero, buyOfferIndexBits[i], 0)
	}
	// verify sell offer id
	sellOfferIdBits := api.ToBinary(tx.SellOffer.OfferId, 24)
	sellAssetId := api.FromBinary(sellOfferIdBits[7:]...)
	sellOfferIndex := api.Sub(tx.SellOffer.OfferId, api.Mul(sellAssetId, OfferSizePerAsset))
	sellOfferIndexBits := api.ToBinary(accountsBefore[sellAccount].AssetsInfo[1].OfferCanceledOrFinalized, OfferSizePerAsset)
	for i := 0; i < OfferSizePerAsset; i++ {
		isZero := api.IsZero(api.Sub(sellOfferIndex, i))
		IsVariableEqual(api, isZero, sellOfferIndexBits[i], 0)
	}
	// buyer should have enough balance
	tx.BuyOffer.AssetAmount = UnpackAmount(api, tx.BuyOffer.AssetAmount)
	IsVariableLessOrEqual(api, flag, tx.BuyOffer.AssetAmount, accountsBefore[buyAccount].AssetsInfo[0].Balance)
	// submitter should have enough balance
	tx.GasFeeAssetAmount = UnpackFee(api, tx.GasFeeAssetAmount)
	IsVariableLessOrEqual(api, flag, tx.GasFeeAssetAmount, accountsBefore[fromAccount].AssetsInfo[0].Balance)
	return pubData, nil
}
