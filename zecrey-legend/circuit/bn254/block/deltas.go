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
	"github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"
)

type AccountDeltaConstraints struct {
	AssetDeltas    [NbAccountAssetsPerAccount]Variable
	LiquidityDelta AccountLiquidityDeltaConstraints
}

type AccountLiquidityDeltaConstraints struct {
	AssetADelta Variable
	AssetBDelta Variable
	LpDelta     Variable
}

func EmptyAccountLiquidityDeltaConstraints() AccountLiquidityDeltaConstraints {
	return AccountLiquidityDeltaConstraints{
		AssetADelta: std.ZeroInt,
		AssetBDelta: std.ZeroInt,
		LpDelta:     std.ZeroInt,
	}
}

type AccountNftDeltaConstraints struct {
	NftIndex       Variable
	NftAssetId     Variable
	NftContentHash Variable
	AssetId        Variable
	AssetAmount    Variable
	NftL1TokenId   Variable
	NftL1Address   Variable
}

func EmptyAccountNftDeltaConstraints() AccountNftDeltaConstraints {
	return AccountNftDeltaConstraints{
		NftIndex:       -1,
		NftAssetId:     -1,
		NftContentHash: 0,
		AssetId:        -1,
		AssetAmount:    0,
		NftL1TokenId:   0,
		NftL1Address:   0,
	}
}

func UpdateAccounts(
	api API,
	accountInfos [NbAccountsPerTx]std.AccountConstraints,
	accountDeltas [NbAccountsPerTx]AccountDeltaConstraints,
	accountNftDeltas [NbAccountsPerTx]AccountNftDeltaConstraints,
) (AccountsInfoAfter [NbAccountsPerTx]std.AccountConstraints) {
	AccountsInfoAfter = accountInfos
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			AccountsInfoAfter[i].AssetsInfo[j].Balance = api.Add(
				accountInfos[i].AssetsInfo[j].Balance,
				accountDeltas[i].AssetDeltas[j])
		}
		AccountsInfoAfter[i].LiquidityInfo.AssetAAmount = api.Add(
			accountInfos[i].LiquidityInfo.AssetAAmount,
			accountDeltas[i].LiquidityDelta.AssetADelta,
		)
		AccountsInfoAfter[i].LiquidityInfo.AssetBAmount = api.Add(
			accountInfos[i].LiquidityInfo.AssetBAmount,
			accountDeltas[i].LiquidityDelta.AssetBDelta,
		)
		AccountsInfoAfter[i].LiquidityInfo.LpAmount = api.Add(
			accountInfos[i].LiquidityInfo.LpAmount,
			accountDeltas[i].LiquidityDelta.LpDelta,
		)
		AccountsInfoAfter[i].NftInfo.NftIndex = accountNftDeltas[i].NftIndex
		AccountsInfoAfter[i].NftInfo.NftAssetId = accountNftDeltas[i].NftAssetId
		AccountsInfoAfter[i].NftInfo.NftContentHash = accountNftDeltas[i].NftContentHash
		AccountsInfoAfter[i].NftInfo.AssetId = accountNftDeltas[i].AssetId
		AccountsInfoAfter[i].NftInfo.AssetAmount = accountNftDeltas[i].AssetAmount
		AccountsInfoAfter[i].NftInfo.NftL1TokenId = accountNftDeltas[i].NftL1TokenId
		AccountsInfoAfter[i].NftInfo.NftL1Address = accountNftDeltas[i].NftL1Address
	}
	return AccountsInfoAfter
}

func GetAccountDeltasFromDeposit(
	api API,
	txInfo DepositTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.AssetAmount,
			txInfo.AssetAmount,
			txInfo.AssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		deltas[i] = deltas[0]
	}
	return deltas
}

func GetAccountDeltasFromDepositNft(
	api API,
	txInfo DepositNftTxConstraints,
) (deltas [NbAccountsPerTx]AccountNftDeltaConstraints) {
	deltas[0] = AccountNftDeltaConstraints{
		NftIndex:       txInfo.NftIndex,
		NftAssetId:     txInfo.NftAssetId,
		AssetId:        -1,
		AssetAmount:    0,
		NftContentHash: txInfo.NftContentHash,
		NftL1TokenId:   txInfo.NftL1TokenId,
		NftL1Address:   txInfo.NftL1Address,
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		deltas[i] = deltas[0]
	}
	return deltas
}

func GetAccountDeltasFromTransfer(
	api API,
	txInfo TransferTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	// if assetId == gasFeeAssetId, compute delta for asset A
	notSameAsset := api.Sub(txInfo.AssetId, txInfo.GasFeeAssetId)
	assetADelta := api.Add(txInfo.AssetAmount, txInfo.GasFeeAssetAmount)
	assetADelta = api.Select(notSameAsset, txInfo.AssetAmount, assetADelta)
	assetGasDelta := api.Select(notSameAsset, txInfo.GasFeeAssetAmount, assetADelta)
	assetADelta = api.Neg(assetADelta)
	assetGasDelta = api.Neg(assetGasDelta)
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			// assetA
			assetADelta,
			// assetGas
			assetGasDelta,
			// assetGas
			assetGasDelta,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[1] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.AssetAmount,
			txInfo.AssetAmount,
			txInfo.AssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[2] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[3] = deltas[2]
	return deltas
}

func GetAccountDeltasFromSwap(
	api API,
	txInfo SwapTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	notSameAssetA := api.Sub(txInfo.AssetAId, txInfo.GasFeeAssetId)
	notSameAssetB := api.Sub(txInfo.AssetBId, txInfo.GasFeeAssetId)
	assetADelta := api.Add(txInfo.AssetAAmount, txInfo.GasFeeAssetAmount)
	assetADelta = api.Select(notSameAssetA, txInfo.AssetAAmount, assetADelta)
	assetGasDelta := api.Select(notSameAssetA, txInfo.GasFeeAssetAmount, assetADelta)
	assetBDelta := api.Sub(txInfo.AssetBAmountDelta, txInfo.GasFeeAssetAmount)
	assetBDelta = api.Select(notSameAssetB, txInfo.AssetBAmountDelta, assetBDelta)
	assetGasDelta = api.Select(notSameAssetB, assetGasDelta, assetBDelta)
	assetADelta = api.Neg(assetADelta)
	assetGasDelta = api.Neg(assetGasDelta)
	// from account
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			// assetA
			assetADelta,
			// assetB
			assetBDelta,
			// assetGas
			assetGasDelta,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	// to account
	deltas[1] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			std.ZeroInt,
			std.ZeroInt,
			std.ZeroInt,
		},
		LiquidityDelta: AccountLiquidityDeltaConstraints{
			AssetADelta: txInfo.AssetAAmount,
			AssetBDelta: api.Neg(txInfo.AssetBAmountDelta),
			LpDelta:     std.ZeroInt,
		},
	}
	deltas[2] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[3] = deltas[2]
	return deltas
}

func GetAccountDeltasFromAddLiquidity(
	api API,
	txInfo AddLiquidityTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	notSameAssetA := api.Sub(txInfo.AssetAId, txInfo.GasFeeAssetId)
	notSameAssetB := api.Sub(txInfo.AssetBId, txInfo.GasFeeAssetId)
	assetADelta := api.Add(txInfo.AssetAAmount, txInfo.GasFeeAssetAmount)
	assetADelta = api.Select(notSameAssetA, txInfo.AssetAAmount, assetADelta)
	assetGasDelta := api.Select(notSameAssetA, txInfo.GasFeeAssetAmount, assetADelta)
	assetBDelta := api.Add(txInfo.AssetBAmount, txInfo.GasFeeAssetAmount)
	assetBDelta = api.Select(notSameAssetB, txInfo.AssetBAmount, assetBDelta)
	assetGasDelta = api.Select(notSameAssetB, assetGasDelta, assetBDelta)
	assetADelta = api.Neg(assetADelta)
	assetBDelta = api.Neg(assetBDelta)
	assetGasDelta = api.Neg(assetGasDelta)
	// from account
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			// assetA
			assetADelta,
			// assetB
			assetBDelta,
			// assetGas
			assetGasDelta,
		},
		LiquidityDelta: AccountLiquidityDeltaConstraints{
			AssetADelta: std.ZeroInt,
			AssetBDelta: std.ZeroInt,
			LpDelta:     txInfo.LpAmount,
		},
	}
	// to account
	deltas[1] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			std.ZeroInt,
			std.ZeroInt,
			std.ZeroInt,
		},
		LiquidityDelta: AccountLiquidityDeltaConstraints{
			AssetADelta: txInfo.AssetAAmount,
			AssetBDelta: txInfo.AssetBAmount,
			LpDelta:     std.ZeroInt,
		},
	}
	// gas account
	deltas[2] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[3] = deltas[2]
	return deltas
}

func GetAccountDeltasFromRemoveLiquidity(
	api API,
	txInfo RemoveLiquidityTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	notSameAssetA := api.Sub(txInfo.AssetAId, txInfo.GasFeeAssetId)
	notSameAssetB := api.Sub(txInfo.AssetBId, txInfo.GasFeeAssetId)
	assetADelta := api.Sub(txInfo.AssetAAmountDelta, txInfo.GasFeeAssetAmount)
	assetADelta = api.Select(notSameAssetA, txInfo.AssetAAmountDelta, assetADelta)
	assetGasDelta := api.Select(notSameAssetA, txInfo.GasFeeAssetAmount, assetADelta)
	assetBDelta := api.Sub(txInfo.AssetBAmountDelta, txInfo.GasFeeAssetAmount)
	assetBDelta = api.Select(notSameAssetB, txInfo.AssetBAmountDelta, assetBDelta)
	assetGasDelta = api.Select(notSameAssetB, assetGasDelta, assetBDelta)
	assetGasDelta = api.Neg(assetGasDelta)
	// from account
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			// assetA
			assetADelta,
			// assetB
			assetBDelta,
			// assetGas
			assetGasDelta,
		},
		LiquidityDelta: AccountLiquidityDeltaConstraints{
			AssetADelta: std.ZeroInt,
			AssetBDelta: std.ZeroInt,
			LpDelta:     api.Neg(txInfo.LpAmount),
		},
	}
	// to account
	deltas[1] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			std.ZeroInt,
			std.ZeroInt,
			std.ZeroInt,
		},
		LiquidityDelta: AccountLiquidityDeltaConstraints{
			AssetADelta: api.Neg(txInfo.AssetAAmountDelta),
			AssetBDelta: api.Neg(txInfo.AssetBAmountDelta),
			LpDelta:     std.ZeroInt,
		},
	}
	// gas account
	deltas[2] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[3] = deltas[2]
	return deltas
}

func GetAccountDeltasFromWithdraw(
	api API,
	txInfo WithdrawTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	// if assetId == gasFeeAssetId, compute delta for asset A
	notSameAsset := api.Sub(txInfo.AssetId, txInfo.GasFeeAssetId)
	assetADelta := api.Add(txInfo.AssetAmount, txInfo.GasFeeAssetAmount)
	assetADelta = api.Select(notSameAsset, txInfo.AssetAmount, assetADelta)
	assetGasDelta := api.Select(notSameAsset, txInfo.GasFeeAssetAmount, assetADelta)
	assetADelta = api.Neg(assetADelta)
	assetGasDelta = api.Neg(assetGasDelta)
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			// assetA
			assetADelta,
			// assetGas
			assetGasDelta,
			// assetGas
			assetGasDelta,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[1] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[2] = deltas[1]
	deltas[3] = deltas[2]
	return deltas
}

func GetAccountDeltasFromMintNft(
	api API,
	txInfo MintNftTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints, nftDeltas [NbAccountsPerTx]AccountNftDeltaConstraints) {
	// if assetId == gasFeeAssetId, compute delta for asset A
	assetGasDelta := api.Neg(txInfo.GasFeeAssetAmount)
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			// assetA
			assetGasDelta,
			// assetGas
			assetGasDelta,
			// assetA
			assetGasDelta,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[1] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[2] = deltas[1]
	deltas[3] = deltas[2]
	// nft deltas
	nftDeltas[0] = AccountNftDeltaConstraints{
		NftIndex:       txInfo.NftIndex,
		NftAssetId:     txInfo.NftAssetId,
		AssetId:        -1,
		AssetAmount:    0,
		NftContentHash: txInfo.NftContentHash,
		NftL1TokenId:   -1,
		NftL1Address:   0,
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		nftDeltas[i] = nftDeltas[i-1]
	}
	return deltas, nftDeltas
}

func GetAccountDeltasFromTransferNft(
	api API,
	txInfo TransferNftTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints, nftDeltas [NbAccountsPerTx]AccountNftDeltaConstraints) {
	assetGasDelta := api.Neg(txInfo.GasFeeAssetAmount)
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			// assetGas
			assetGasDelta,
			// assetGas
			assetGasDelta,
			// assetGas
			assetGasDelta,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[1] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[2] = deltas[1]
	deltas[3] = deltas[2]
	// nft deltas
	// from account
	nftDeltas[0] = EmptyAccountNftDeltaConstraints()
	// to account
	nftDeltas[1] = AccountNftDeltaConstraints{
		NftIndex:       txInfo.NftIndex,
		NftAssetId:     txInfo.ToNftAssetId,
		NftContentHash: txInfo.NftContentHash,
		AssetId:        -1,
		AssetAmount:    0,
		NftL1TokenId:   txInfo.NftL1TokenId,
		NftL1Address:   txInfo.NftL1Address,
	}
	nftDeltas[2] = nftDeltas[1]
	nftDeltas[3] = nftDeltas[2]
	return deltas, nftDeltas
}

func GetAccountDeltasFromSetNftPrice(
	api API,
	txInfo SetNftPriceTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints, nftDeltas [NbAccountsPerTx]AccountNftDeltaConstraints) {
	// if assetId == gasFeeAssetId, compute delta for asset A
	assetGasDelta := api.Neg(txInfo.GasFeeAssetAmount)
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			// assetA
			assetGasDelta,
			// assetGas
			assetGasDelta,
			// assetA
			assetGasDelta,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[1] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[2] = deltas[0]
	deltas[3] = deltas[0]
	// nft deltas
	// from account
	nftDeltas[0] = AccountNftDeltaConstraints{
		NftIndex:       txInfo.NftIndex,
		NftAssetId:     txInfo.NftAssetId,
		NftContentHash: txInfo.NftContentHash,
		AssetId:        txInfo.AssetId,
		AssetAmount:    txInfo.AssetAmount,
		NftL1TokenId:   txInfo.NftL1TokenId,
		NftL1Address:   txInfo.NftL1Address,
	}
	for i := 1; i < NbAccountsPerTx; i++ {
		nftDeltas[i] = nftDeltas[i-1]
	}
	return deltas, nftDeltas
}

func GetAccountDeltasFromBuyNft(
	api API,
	txInfo BuyNftTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints, nftDeltas [NbAccountsPerTx]AccountNftDeltaConstraints) {
	// if assetId == gasFeeAssetId, compute delta for asset A
	notSameAsset := api.Sub(txInfo.AssetId, txInfo.GasFeeAssetId)
	assetADelta := api.Add(txInfo.AssetAmount, txInfo.GasFeeAssetAmount)
	assetADelta = api.Select(notSameAsset, txInfo.AssetAmount, assetADelta)
	assetGasDelta := api.Select(notSameAsset, txInfo.GasFeeAssetAmount, assetADelta)
	assetADelta = api.Neg(assetADelta)
	assetGasDelta = api.Neg(assetGasDelta)
	// from account
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			// assetA
			assetADelta,
			// assetGas
			assetGasDelta,
			// assetA
			assetADelta,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	// compute treasury fee
	treasuryFee := api.Div(api.Mul(txInfo.AssetAmount, txInfo.TreasuryFeeRate), 10000)
	assetAForToDelta := api.Sub(txInfo.AssetAmount, treasuryFee)
	// to account
	deltas[1] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			assetAForToDelta,
			assetAForToDelta,
			assetAForToDelta,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	// treasury account
	deltas[2] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			treasuryFee,
			treasuryFee,
			treasuryFee,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	// gas account
	deltas[3] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	// nft deltas
	// buyer account
	nftDeltas[0] = AccountNftDeltaConstraints{
		NftIndex:       txInfo.NftIndex,
		NftAssetId:     txInfo.NftAssetId,
		NftContentHash: txInfo.NftContentHash,
		AssetId:        -1,
		AssetAmount:    0,
		NftL1TokenId:   txInfo.NftL1TokenId,
		NftL1Address:   txInfo.NftL1Address,
	}
	// owner account
	nftDeltas[1] = EmptyAccountNftDeltaConstraints()
	nftDeltas[2] = nftDeltas[1]
	nftDeltas[3] = nftDeltas[2]
	return deltas, nftDeltas
}

func GetAccountDeltasFromWithdrawNft(
	api API,
	txInfo WithdrawNftTxConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints, nftDeltas [NbAccountsPerTx]AccountNftDeltaConstraints) {
	// if assetId == gasFeeAssetId, compute delta for asset A
	assetGasDelta := api.Neg(txInfo.GasFeeAssetAmount)
	deltas[0] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			// assetA
			assetGasDelta,
			// assetGas
			assetGasDelta,
			// assetA
			assetGasDelta,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[1] = AccountDeltaConstraints{
		AssetDeltas: [3]Variable{
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
			txInfo.GasFeeAssetAmount,
		},
		LiquidityDelta: EmptyAccountLiquidityDeltaConstraints(),
	}
	deltas[2] = deltas[1]
	deltas[3] = deltas[2]
	// nft deltas
	nftDeltas[0] = EmptyAccountNftDeltaConstraints()
	for i := 1; i < NbAccountsPerTx; i++ {
		nftDeltas[i] = nftDeltas[i-1]
	}
	return deltas, nftDeltas
}
