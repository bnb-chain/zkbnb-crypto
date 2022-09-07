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

package block

import (
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/std"
)

type AccountDeltaConstraints struct {
	AccountNameHash Variable
	PubKey          std.EcdsaPkConstraints
}

type AccountAssetDeltaConstraints struct {
	BalanceDelta             Variable
	LpDelta                  Variable
	OfferCanceledOrFinalized Variable
}

func EmptyAccountAssetDeltaConstraints() AccountAssetDeltaConstraints {
	return AccountAssetDeltaConstraints{
		BalanceDelta:             std.ZeroInt,
		LpDelta:                  std.ZeroInt,
		OfferCanceledOrFinalized: std.ZeroInt,
	}
}

func UpdateAccounts(
	api API,
	accountInfos [NbAccountsPerTx]std.AccountConstraints,
	accountDeltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
) (AccountsInfoAfter [NbAccountsPerTx]std.AccountConstraints) {
	AccountsInfoAfter = accountInfos
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			AccountsInfoAfter[i].AssetsInfo[j].Balance = api.Add(
				accountInfos[i].AssetsInfo[j].Balance,
				accountDeltas[i][j].BalanceDelta)

			AccountsInfoAfter[i].AssetsInfo[j].LpAmount = api.Add(
				accountInfos[i].AssetsInfo[j].LpAmount,
				accountDeltas[i][j].LpDelta)
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

func GetAccountDeltaFromRegisterZNS(
	txInfo RegisterZnsTxConstraints,
) (accountDelta AccountDeltaConstraints) {
	accountDelta = AccountDeltaConstraints{
		AccountNameHash: txInfo.AccountNameHash,
		PubKey:          txInfo.PubKey,
	}
	return accountDelta
}

func GetLiquidityDeltaFromCreatePair(
	txInfo CreatePairTxConstraints,
) (liquidityDelta LiquidityDeltaConstraints) {
	liquidityDelta = LiquidityDeltaConstraints{
		AssetAId:             txInfo.AssetAId,
		AssetBId:             txInfo.AssetBId,
		AssetADelta:          std.ZeroInt,
		AssetBDelta:          std.ZeroInt,
		LpDelta:              std.ZeroInt,
		KLast:                std.ZeroInt,
		FeeRate:              txInfo.FeeRate,
		TreasuryAccountIndex: txInfo.TreasuryAccountIndex,
		TreasuryRate:         txInfo.TreasuryRate,
	}
	return liquidityDelta
}

func GetLiquidityDeltaFromUpdatePairRate(
	txInfo UpdatePairRateTxConstraints,
	liquidityBefore LiquidityConstraints,
) (liquidityDelta LiquidityDeltaConstraints) {
	liquidityDelta = LiquidityDeltaConstraints{
		AssetAId:             liquidityBefore.AssetAId,
		AssetBId:             liquidityBefore.AssetBId,
		AssetADelta:          std.ZeroInt,
		AssetBDelta:          std.ZeroInt,
		LpDelta:              std.ZeroInt,
		KLast:                liquidityBefore.KLast,
		FeeRate:              txInfo.FeeRate,
		TreasuryAccountIndex: txInfo.TreasuryAccountIndex,
		TreasuryRate:         txInfo.TreasuryRate,
	}
	return liquidityDelta
}

func GetAssetDeltasFromDeposit(
	txInfo DepositTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints) {
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.AssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	return deltas
}

func GetAssetDeltasFromCreateCollection(
	api API,
	txInfo CreateCollectionTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 2; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	return deltas
}

func GetNftDeltaFromDepositNft(
	txInfo DepositNftTxConstraints,
) (nftDelta NftDeltaConstraints) {
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: txInfo.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.AccountIndex,
		NftContentHash:      txInfo.NftContentHash,
		NftL1Address:        txInfo.NftL1Address,
		NftL1TokenId:        txInfo.NftL1TokenId,
		CreatorTreasuryRate: txInfo.CreatorTreasuryRate,
		CollectionId:        txInfo.CollectionId,
	}
	return nftDelta
}

func GetAssetDeltasFromTransfer(
	api API,
	txInfo TransferTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             api.Neg(txInfo.AssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset Gas
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// to account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.AssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[2] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	for i := 3; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	return deltas
}

func GetAssetDeltasAndLiquidityDeltaFromSwap(
	api API,
	txInfo SwapTxConstraints,
	liquidityBefore LiquidityConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, liquidityDelta LiquidityDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             api.Neg(txInfo.AssetAAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset B
		{
			BalanceDelta:             txInfo.AssetBAmountDelta,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset gas
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset gas
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 2; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	isSameAssetA := api.IsZero(api.Sub(txInfo.AssetAId, liquidityBefore.AssetAId))
	negAssetBAmount := api.Neg(txInfo.AssetBAmountDelta)
	assetADelta := api.Select(isSameAssetA, txInfo.AssetAAmount, negAssetBAmount)
	assetBDelta := api.Select(isSameAssetA, negAssetBAmount, txInfo.AssetAAmount)
	liquidityDelta = LiquidityDeltaConstraints{
		AssetAId:             liquidityBefore.AssetAId,
		AssetBId:             liquidityBefore.AssetBId,
		AssetADelta:          assetADelta,
		AssetBDelta:          assetBDelta,
		LpDelta:              std.ZeroInt,
		KLast:                liquidityBefore.KLast,
		FeeRate:              liquidityBefore.FeeRate,
		TreasuryAccountIndex: liquidityBefore.TreasuryAccountIndex,
		TreasuryRate:         liquidityBefore.TreasuryRate,
	}
	return deltas, liquidityDelta
}

// TODO treasury lp
func GetAssetDeltasAndLiquidityDeltaFromAddLiquidity(
	api API,
	txInfo AddLiquidityTxConstraints,
	liquidityBefore LiquidityConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, liquidityDelta LiquidityDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             api.Neg(txInfo.AssetAAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset B
		{
			BalanceDelta:             api.Neg(txInfo.AssetBAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset gas
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset lp
		{
			BalanceDelta:             std.ZeroInt,
			LpDelta:                  txInfo.LpAmount,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
	}
	// treasury account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             std.ZeroInt,
			LpDelta:                  txInfo.TreasuryAmount,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[2] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 3; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	poolA := api.Add(liquidityBefore.AssetA, txInfo.AssetAAmount)
	poolB := api.Add(liquidityBefore.AssetB, txInfo.AssetBAmount)
	liquidityDelta = LiquidityDeltaConstraints{
		AssetAId:             liquidityBefore.AssetAId,
		AssetBId:             liquidityBefore.AssetBId,
		AssetADelta:          txInfo.AssetAAmount,
		AssetBDelta:          txInfo.AssetBAmount,
		LpDelta:              txInfo.LpAmount,
		KLast:                api.Mul(poolA, poolB),
		FeeRate:              liquidityBefore.FeeRate,
		TreasuryAccountIndex: liquidityBefore.TreasuryAccountIndex,
		TreasuryRate:         liquidityBefore.TreasuryRate,
	}
	return deltas, liquidityDelta
}

// TODO treasury lp
func GetAssetDeltasAndLiquidityDeltaFromRemoveLiquidity(
	api API,
	txInfo RemoveLiquidityTxConstraints,
	liquidityBefore LiquidityConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, liquidityDelta LiquidityDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             txInfo.AssetAAmountDelta,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset B
		{
			BalanceDelta:             txInfo.AssetBAmountDelta,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset gas
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset lp
		{
			BalanceDelta:             std.ZeroInt,
			LpDelta:                  api.Neg(txInfo.LpAmount),
			OfferCanceledOrFinalized: std.ZeroInt,
		},
	}
	// treasury account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             std.ZeroInt,
			LpDelta:                  txInfo.TreasuryAmount,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[2] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 3; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	poolA := api.Sub(liquidityBefore.AssetA, txInfo.AssetAAmountDelta)
	poolB := api.Sub(liquidityBefore.AssetB, txInfo.AssetBAmountDelta)
	liquidityDelta = LiquidityDeltaConstraints{
		AssetAId:             liquidityBefore.AssetAId,
		AssetBId:             liquidityBefore.AssetBId,
		AssetADelta:          api.Neg(txInfo.AssetAAmountDelta),
		AssetBDelta:          api.Neg(txInfo.AssetBAmountDelta),
		LpDelta:              api.Neg(txInfo.LpAmount),
		KLast:                api.Mul(poolA, poolB),
		FeeRate:              liquidityBefore.FeeRate,
		TreasuryAccountIndex: liquidityBefore.TreasuryAccountIndex,
		TreasuryRate:         liquidityBefore.TreasuryRate,
	}
	return deltas, liquidityDelta
}

func GetAssetDeltasFromWithdraw(
	api API,
	txInfo WithdrawTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             api.Neg(txInfo.AssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset gas
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 2; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	return deltas
}

func GetAssetDeltasAndNftDeltaFromMintNft(
	api API,
	txInfo MintNftTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, nftDelta NftDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	deltas[2] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 3; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: txInfo.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.ToAccountIndex,
		NftContentHash:      txInfo.NftContentHash,
		NftL1Address:        std.ZeroInt,
		NftL1TokenId:        std.ZeroInt,
		CreatorTreasuryRate: txInfo.CreatorTreasuryRate,
		CollectionId:        txInfo.CollectionId,
	}
	return deltas, nftDelta
}

func GetAssetDeltasAndNftDeltaFromTransferNft(
	api API,
	txInfo TransferNftTxConstraints,
	nftBefore NftConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, nftDelta NftDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[2] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 3; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: nftBefore.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.ToAccountIndex,
		NftContentHash:      nftBefore.NftContentHash,
		NftL1Address:        nftBefore.NftL1Address,
		NftL1TokenId:        nftBefore.NftL1TokenId,
		CreatorTreasuryRate: nftBefore.CreatorTreasuryRate,
		CollectionId:        nftBefore.CollectionId,
	}
	return deltas, nftDelta
}

// TODO creator & treasury fee
func GetAssetDeltasAndNftDeltaFromAtomicMatch(
	api API,
	flag Variable,
	txInfo AtomicMatchTxConstraints,
	accountsBefore [NbAccountsPerTx]std.AccountConstraints,
	nftBefore NftConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, nftDelta NftDeltaConstraints) {
	// submitter
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// TODO
	creatorAmountVar := api.Mul(txInfo.BuyOffer.AssetAmount, nftBefore.CreatorTreasuryRate)
	treasuryAmountVar := api.Mul(txInfo.BuyOffer.AssetAmount, txInfo.BuyOffer.TreasuryRate)
	creatorAmountVar = api.Div(creatorAmountVar, RateBase)
	treasuryAmountVar = api.Div(treasuryAmountVar, RateBase)
	sellerAmount := api.Sub(txInfo.BuyOffer.AssetAmount, api.Add(creatorAmountVar, treasuryAmountVar))
	buyerDelta := api.Neg(txInfo.BuyOffer.AssetAmount)
	sellerDelta := sellerAmount
	// buyer
	buyOfferIdBits := api.ToBinary(txInfo.BuyOffer.OfferId, 24)
	buyAssetId := api.FromBinary(buyOfferIdBits[7:]...)
	buyOfferIndex := api.Sub(txInfo.BuyOffer.OfferId, api.Mul(buyAssetId, OfferSizePerAsset))
	buyOfferBits := api.ToBinary(accountsBefore[1].AssetsInfo[0].OfferCanceledOrFinalized)
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
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		{
			BalanceDelta:             std.ZeroInt,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: buyOfferCanceledOrFinalized,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// sell
	sellOfferIdBits := api.ToBinary(txInfo.SellOffer.OfferId, 24)
	sellAssetId := api.FromBinary(sellOfferIdBits[7:]...)
	sellOfferIndex := api.Sub(txInfo.SellOffer.OfferId, api.Mul(sellAssetId, OfferSizePerAsset))
	sellOfferBits := api.ToBinary(accountsBefore[2].AssetsInfo[0].OfferCanceledOrFinalized)
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
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		{
			BalanceDelta:             std.ZeroInt,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: sellOfferCanceledOrFinalized,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// creator account
	deltas[3] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             creatorAmountVar,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[4] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta:             treasuryAmountVar,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		// asset Gas
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: nftBefore.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.BuyOffer.AccountIndex,
		NftContentHash:      nftBefore.NftContentHash,
		NftL1Address:        nftBefore.NftL1Address,
		NftL1TokenId:        nftBefore.NftL1TokenId,
		CreatorTreasuryRate: nftBefore.CreatorTreasuryRate,
		CollectionId:        nftBefore.CollectionId,
	}
	return deltas, nftDelta
}

func GetAssetDeltasFromCancelOffer(
	api API,
	flag Variable,
	txInfo CancelOfferTxConstraints,
	accountsBefore [NbAccountsPerTx]std.AccountConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints) {
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
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		{
			BalanceDelta:             std.ZeroInt,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: fromOfferCanceledOrFinalized,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 2; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	return deltas
}

func GetAssetDeltasAndNftDeltaFromWithdrawNft(
	api API,
	txInfo WithdrawNftTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, nftDelta NftDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// creator account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[2] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             txInfo.GasFeeAssetAmount,
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 3; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: std.ZeroInt,
		OwnerAccountIndex:   std.ZeroInt,
		NftContentHash:      std.ZeroInt,
		NftL1Address:        std.ZeroInt,
		NftL1TokenId:        std.ZeroInt,
		CreatorTreasuryRate: std.ZeroInt,
		CollectionId:        std.ZeroInt,
	}
	return deltas, nftDelta
}

func GetAssetDeltasFromFullExit(
	api API,
	txInfo FullExitTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta:             api.Neg(txInfo.AssetAmount),
			LpDelta:                  std.ZeroInt,
			OfferCanceledOrFinalized: std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		deltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	return deltas
}

func GetNftDeltaFromFullExitNft() (nftDelta NftDeltaConstraints) {
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: std.ZeroInt,
		OwnerAccountIndex:   std.ZeroInt,
		NftContentHash:      std.ZeroInt,
		NftL1Address:        std.ZeroInt,
		NftL1TokenId:        std.ZeroInt,
		CreatorTreasuryRate: std.ZeroInt,
		CollectionId:        std.ZeroInt,
	}
	return nftDelta
}
