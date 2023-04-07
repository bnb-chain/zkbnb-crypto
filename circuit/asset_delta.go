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
	"github.com/consensys/gnark/std/signature/eddsa"

	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

type AccountDeltaConstraints struct {
	L1Address Variable
	PubKey    eddsa.PublicKey
}

type AccountAssetDeltaConstraints struct {
	BalanceDelta             Variable
	OfferCanceledOrFinalized Variable
}

type GasDeltaConstraints struct {
	AssetId      Variable
	BalanceDelta Variable
}

func EmptyAccountAssetDeltaConstraints() AccountAssetDeltaConstraints {
	return AccountAssetDeltaConstraints{
		BalanceDelta:             types.ZeroInt,
		OfferCanceledOrFinalized: types.ZeroInt,
	}
}

func EmptyGasDeltaConstraints(assetId Variable) GasDeltaConstraints {
	return GasDeltaConstraints{
		AssetId:      assetId,
		BalanceDelta: types.ZeroInt,
	}
}

func UpdateAccounts(
	api API,
	accountInfos [NbAccountsPerTx]types.AccountConstraints,
	accountDeltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
) (AccountsInfoAfter [NbAccountsPerTx]types.AccountConstraints) {
	AccountsInfoAfter = accountInfos
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			AccountsInfoAfter[i].AssetsInfo[j].Balance = api.Add(
				accountInfos[i].AssetsInfo[j].Balance,
				accountDeltas[i][j].BalanceDelta)

			isZero := api.IsZero(accountDeltas[i][j].OfferCanceledOrFinalized)
			AccountsInfoAfter[i].AssetsInfo[j].OfferCanceledOrFinalized = api.Select(
				isZero,
				AccountsInfoAfter[i].AssetsInfo[j].OfferCanceledOrFinalized,
				accountDeltas[i][j].OfferCanceledOrFinalized,
			)
		}
	}
	return AccountsInfoAfter
}

func GetGasDeltas(gasFeeAssetId, gasFeeAssetAmount Variable) (
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints) {
	gasDeltas[0].AssetId = gasFeeAssetId
	gasDeltas[0].BalanceDelta = gasFeeAssetAmount

	for i := 1; i < NbGasAssetsPerTx; i++ {
		gasDeltas[i] = EmptyGasDeltaConstraints(gasFeeAssetId)
	}
	return gasDeltas
}

func GetAccountDeltaFromChangePubKey(
	api API,
	txInfo ChangePubKeyTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints,
	accountDelta AccountDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	gasDeltas = GetGasDeltas(txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount)
	accountDelta = AccountDeltaConstraints{
		PubKey: txInfo.PubKey,
	}
	return deltas, gasDeltas, accountDelta
}

func GetAssetDeltasFromDeposit(
	txInfo DepositTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
	accountDelta AccountDeltaConstraints) {
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.AssetAmount,
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	accountDelta = AccountDeltaConstraints{
		L1Address: txInfo.L1Address,
	}
	return deltas, accountDelta
}

func GetAssetDeltasFromCreateCollection(
	api API,
	txInfo CreateCollectionTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	gasDeltas = GetGasDeltas(txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount)
	return deltas, gasDeltas
}

func GetNftDeltaFromDepositNft(
	txInfo DepositNftTxConstraints,
) (nftDelta NftDeltaConstraints,
	accountDelta AccountDeltaConstraints) {
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: txInfo.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.AccountIndex,
		NftContentHash:      txInfo.NftContentHash,
		RoyaltyRate:         txInfo.RoyaltyRate,
		CollectionId:        txInfo.CollectionId,
	}
	accountDelta = AccountDeltaConstraints{
		L1Address: txInfo.L1Address,
	}
	return nftDelta, accountDelta
}

func GetAssetDeltasFromTransfer(
	api API,
	txInfo TransferTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints,
	accountDelta AccountDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             api.Neg(txInfo.AssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		// asset Gas
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
	}
	// to account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.AssetAmount,
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 2; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	gasDeltas = GetGasDeltas(txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount)
	accountDelta = AccountDeltaConstraints{
		L1Address: txInfo.ToL1Address,
	}
	return deltas, gasDeltas, accountDelta
}

func GetAssetDeltasFromWithdraw(
	api API,
	txInfo WithdrawTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             api.Neg(txInfo.AssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		// asset gas
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	gasDeltas = GetGasDeltas(txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount)
	return deltas, gasDeltas
}

func GetAssetDeltasAndNftDeltaFromMintNft(
	api API,
	txInfo MintNftTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
	nftDelta NftDeltaConstraints,
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 2; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: txInfo.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.ToAccountIndex,
		NftContentHash:      txInfo.NftContentHash,
		RoyaltyRate:         txInfo.RoyaltyRate,
		CollectionId:        txInfo.CollectionId,
	}
	gasDeltas = GetGasDeltas(txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount)
	return deltas, nftDelta, gasDeltas
}

func GetAssetDeltasAndNftDeltaFromTransferNft(
	api API,
	txInfo TransferNftTxConstraints,
	nftBefore NftConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
	nftDelta NftDeltaConstraints,
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints, accountDelta AccountDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 2; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: nftBefore.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.ToAccountIndex,
		NftContentHash:      nftBefore.NftContentHash,
		RoyaltyRate:         nftBefore.RoyaltyRate,
		CollectionId:        nftBefore.CollectionId,
	}
	gasDeltas = GetGasDeltas(txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount)
	accountDelta = AccountDeltaConstraints{
		L1Address: txInfo.ToL1Address,
	}
	return deltas, nftDelta, gasDeltas, accountDelta
}

func GetAssetDeltasAndNftDeltaFromAtomicMatch(
	api API,
	flag Variable,
	txInfo AtomicMatchTxConstraints,
	accountsBefore [NbAccountsPerTx]types.AccountConstraints,
	nftBefore NftConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
	nftDelta NftDeltaConstraints,
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints) {
	// submitter
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	// TODO
	RoyaltyAmountVar := api.Mul(txInfo.BuyOffer.AssetAmount, nftBefore.RoyaltyRate)
	buyChannelAmountVar := api.Mul(txInfo.BuyOffer.AssetAmount, txInfo.BuyOffer.ChannelRate)
	sellChannelAmountVar := api.Mul(txInfo.BuyOffer.AssetAmount, txInfo.SellOffer.ChannelRate)
	RoyaltyAmountVar = api.Div(RoyaltyAmountVar, RateBase)
	buyChannelAmountVar = api.Div(buyChannelAmountVar, RateBase)
	sellChannelAmountVar = api.Div(sellChannelAmountVar, RateBase)

	sellerAmount := api.Sub(txInfo.BuyOffer.AssetAmount, sellChannelAmountVar)
	buyerDelta := api.Neg(api.Add(txInfo.BuyOffer.AssetAmount, RoyaltyAmountVar, buyChannelAmountVar, txInfo.BuyOffer.ProtocolAmount))
	sellerDelta := sellerAmount
	// buyer
	buyOfferIdBits := api.ToBinary(txInfo.BuyOffer.OfferId, 23)
	buyAssetId := api.FromBinary(buyOfferIdBits[7:]...)
	buyOfferIndex := api.Sub(txInfo.BuyOffer.OfferId, api.Mul(buyAssetId, OfferSizePerAsset))
	buyOfferBits := api.ToBinary(accountsBefore[1].AssetsInfo[1].OfferCanceledOrFinalized)
	// TODO need to optimize here
	for i := 0; i < OfferSizePerAsset; i++ {
		isZero := api.IsZero(api.Sub(buyOfferIndex, i))
		isChange := api.And(isZero, flag)
		buyOfferBits[i] = api.Select(isChange, 1, buyOfferBits[i])
	}
	buyOfferCanceledOrFinalized := api.FromBinary(buyOfferBits...)
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             buyerDelta,
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		{
			BalanceDelta:             types.ZeroInt,
			OfferCanceledOrFinalized: buyOfferCanceledOrFinalized,
		},
	}
	// sell
	sellOfferIdBits := api.ToBinary(txInfo.SellOffer.OfferId, 23)
	sellAssetId := api.FromBinary(sellOfferIdBits[7:]...)
	sellOfferIndex := api.Sub(txInfo.SellOffer.OfferId, api.Mul(sellAssetId, OfferSizePerAsset))
	sellOfferBits := api.ToBinary(accountsBefore[2].AssetsInfo[1].OfferCanceledOrFinalized)
	// TODO need to optimize here
	for i := 0; i < OfferSizePerAsset; i++ {
		isZero := api.IsZero(api.Sub(sellOfferIndex, i))
		isChange := api.And(isZero, flag)
		sellOfferBits[i] = api.Select(isChange, 1, sellOfferBits[i])
	}
	sellOfferCanceledOrFinalized := api.FromBinary(sellOfferBits...)
	deltas[2] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             sellerDelta,
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		{
			BalanceDelta:             types.ZeroInt,
			OfferCanceledOrFinalized: sellOfferCanceledOrFinalized,
		},
	}
	// creator account
	deltas[3] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             RoyaltyAmountVar,
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	// buy Chanel account
	deltas[4] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             buyChannelAmountVar,
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	// sell Chanel account
	deltas[5] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             sellChannelAmountVar,
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	// protocol account
	deltas[6] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             txInfo.BuyOffer.ProtocolAmount,
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: nftBefore.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.BuyOffer.AccountIndex,
		NftContentHash:      nftBefore.NftContentHash,
		RoyaltyRate:         nftBefore.RoyaltyRate,
		CollectionId:        nftBefore.CollectionId,
	}

	//gasDeltas[0].AssetId = txInfo.BuyOffer.AssetId
	//gasDeltas[0].BalanceDelta = txInfo.BuyOffer.ProtocolAmount

	gasDeltas[0].AssetId = txInfo.GasFeeAssetId
	gasDeltas[0].BalanceDelta = txInfo.GasFeeAssetAmount

	for i := 1; i < NbGasAssetsPerTx; i++ {
		gasDeltas[i] = EmptyGasDeltaConstraints(txInfo.GasFeeAssetId)
	}

	return deltas, nftDelta, gasDeltas
}

func GetAssetDeltasFromCancelOffer(
	api API,
	flag Variable,
	txInfo CancelOfferTxConstraints,
	accountsBefore [NbAccountsPerTx]types.AccountConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints) {
	// from account
	offerIdBits := api.ToBinary(txInfo.OfferId, 24)
	assetId := api.FromBinary(offerIdBits[7:]...)
	offerIndex := api.Sub(txInfo.OfferId, api.Mul(assetId, OfferSizePerAsset))
	fromOfferBits := api.ToBinary(accountsBefore[0].AssetsInfo[1].OfferCanceledOrFinalized)
	// TODO need to optimize here
	for i := 0; i < OfferSizePerAsset; i++ {
		isZero := api.IsZero(api.Sub(offerIndex, i))
		isChange := api.And(isZero, flag)
		fromOfferBits[i] = api.Select(isChange, 1, fromOfferBits[i])
	}
	fromOfferCanceledOrFinalized := api.FromBinary(fromOfferBits...)
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset Gas
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		{
			BalanceDelta:             types.ZeroInt,
			OfferCanceledOrFinalized: fromOfferCanceledOrFinalized,
		},
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	gasDeltas = GetGasDeltas(txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount)
	return deltas, gasDeltas
}

func GetAssetDeltasAndNftDeltaFromWithdrawNft(
	api API,
	txInfo WithdrawNftTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
	nftDelta NftDeltaConstraints,
	gasDeltas [NbGasAssetsPerTx]GasDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	// creator account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 2; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: types.ZeroInt,
		OwnerAccountIndex:   types.ZeroInt,
		NftContentHash:      [2]Variable{types.ZeroInt, types.ZeroInt},
		RoyaltyRate:         types.ZeroInt,
		CollectionId:        types.ZeroInt,
	}
	gasDeltas = GetGasDeltas(txInfo.GasFeeAssetId, txInfo.GasFeeAssetAmount)
	return deltas, nftDelta, gasDeltas
}

func GetAssetDeltasFromFullExit(
	api API,
	txInfo FullExitTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.AssetAmount),
			OfferCanceledOrFinalized: types.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	return deltas
}

func GetNftDeltaFromFullExitNft(
	api API,
	flag Variable,
	txInfo FullExitNftTxConstraints,
	accountsBefore [NbAccountsPerTx]types.AccountConstraints,
	nftBefore NftConstraints) (nftDelta NftDeltaConstraints) {
	fromAccount := 0

	txInfoL1Address := api.Select(flag, txInfo.L1Address, 0)
	beforeL1Address := api.Select(flag, accountsBefore[fromAccount].L1Address, 0)
	isFullExitSuccess := api.IsZero(api.Cmp(txInfoL1Address, beforeL1Address))
	isOwner := api.And(isFullExitSuccess, api.And(api.IsZero(api.Sub(txInfo.AccountIndex, nftBefore.OwnerAccountIndex)), flag))
	creatorAccountIndex := api.Select(isOwner, types.ZeroInt, nftBefore.CreatorAccountIndex)
	ownerAccountIndex := api.Select(isOwner, types.ZeroInt, nftBefore.OwnerAccountIndex)
	nftContentHash := [2]Variable{}
	nftContentHash[0] = api.Select(isOwner, types.ZeroInt, nftBefore.NftContentHash[0])
	nftContentHash[1] = api.Select(isOwner, types.ZeroInt, nftBefore.NftContentHash[1])
	royaltyRate := api.Select(isOwner, types.ZeroInt, nftBefore.RoyaltyRate)
	collectionId := api.Select(isOwner, types.ZeroInt, nftBefore.CollectionId)
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: creatorAccountIndex,
		OwnerAccountIndex:   ownerAccountIndex,
		NftContentHash:      nftContentHash,
		RoyaltyRate:         royaltyRate,
		CollectionId:        collectionId,
	}
	return nftDelta
}
