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
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"
)

type AccountDeltaConstraints struct {
	AccountNameHash Variable
	PubKey          eddsa.PublicKey
}

type AccountAssetDeltaConstraints struct {
	BalanceDelta Variable
	LpDelta      Variable
}

func EmptyAccountAssetDeltaConstraints() AccountAssetDeltaConstraints {
	return AccountAssetDeltaConstraints{
		BalanceDelta: std.ZeroInt,
		LpDelta:      std.ZeroInt,
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
		AssetAId:    txInfo.AssetAId,
		AssetBId:    txInfo.AssetBId,
		AssetADelta: std.ZeroInt,
		AssetBDelta: std.ZeroInt,
		LpDelta:     std.ZeroInt,
	}
	return liquidityDelta
}

func GetAssetDeltasFromDeposit(
	txInfo DepositTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints) {
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.AssetAmount,
			LpDelta:      std.ZeroInt,
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

func GetNftDeltaFromDepositNft(
	txInfo DepositNftTxConstraints,
) (nftDelta NftDeltaConstraints) {
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: txInfo.AccountIndex,
		OwnerAccountIndex:   txInfo.AccountIndex,
		NftContentHash:      txInfo.NftContentHash,
		NftL1Address:        txInfo.NftL1Address,
		NftL1TokenId:        txInfo.NftL1TokenId,
		AssetId:             std.ZeroInt,
		AssetAmount:         std.ZeroInt,
		CreatorTreasuryRate: txInfo.CreatorTreasuryRate,
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
			BalanceDelta: api.Neg(txInfo.AssetAmount),
			LpDelta:      std.ZeroInt,
		},
		// asset Gas
		{
			BalanceDelta: api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// to account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.AssetAmount,
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[2] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.GasFeeAssetAmount,
			LpDelta:      std.ZeroInt,
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
			BalanceDelta: api.Neg(txInfo.AssetAAmount),
			LpDelta:      std.ZeroInt,
		},
		// asset B
		{
			BalanceDelta: txInfo.AssetAAmount,
			LpDelta:      std.ZeroInt,
		},
		// asset gas
		{
			BalanceDelta: api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset gas
		{
			BalanceDelta: txInfo.GasFeeAssetAmount,
			LpDelta:      std.ZeroInt,
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
		AssetAId:    liquidityBefore.AssetAId,
		AssetBId:    liquidityBefore.AssetBId,
		AssetADelta: assetADelta,
		AssetBDelta: assetBDelta,
		LpDelta:     std.ZeroInt,
	}
	return deltas, liquidityDelta
}

func GetAssetDeltasAndLiquidityDeltaFromAddLiquidity(
	api API,
	txInfo AddLiquidityTxConstraints,
	liquidityBefore LiquidityConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, liquidityDelta LiquidityDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta: api.Neg(txInfo.AssetAAmount),
			LpDelta:      std.ZeroInt,
		},
		// asset B
		{
			BalanceDelta: api.Neg(txInfo.AssetBAmount),
			LpDelta:      std.ZeroInt,
		},
		// asset lp
		{
			BalanceDelta: std.ZeroInt,
			LpDelta:      txInfo.LpAmount,
		},
		// asset gas
		{
			BalanceDelta: api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:      std.ZeroInt,
		},
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.GasFeeAssetAmount,
			LpDelta:      std.ZeroInt,
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
	liquidityDelta = LiquidityDeltaConstraints{
		AssetAId:    liquidityBefore.AssetAId,
		AssetBId:    liquidityBefore.AssetBId,
		AssetADelta: txInfo.AssetAAmount,
		AssetBDelta: txInfo.AssetBAmount,
		LpDelta:     txInfo.LpAmount,
	}
	return deltas, liquidityDelta
}

func GetAssetDeltasAndLiquidityDeltaFromRemoveLiquidity(
	api API,
	txInfo RemoveLiquidityTxConstraints,
	liquidityBefore LiquidityConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, liquidityDelta LiquidityDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta: txInfo.AssetAAmountDelta,
			LpDelta:      std.ZeroInt,
		},
		// asset B
		{
			BalanceDelta: txInfo.AssetBAmountDelta,
			LpDelta:      std.ZeroInt,
		},
		// asset lp
		{
			BalanceDelta: std.ZeroInt,
			LpDelta:      txInfo.LpAmount,
		},
		// asset gas
		{
			BalanceDelta: api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:      std.ZeroInt,
		},
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.GasFeeAssetAmount,
			LpDelta:      std.ZeroInt,
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
	liquidityDelta = LiquidityDeltaConstraints{
		AssetAId:    liquidityBefore.AssetAId,
		AssetBId:    liquidityBefore.AssetBId,
		AssetADelta: api.Neg(txInfo.AssetAAmountDelta),
		AssetBDelta: api.Neg(txInfo.AssetBAmountDelta),
		LpDelta:     api.Neg(txInfo.LpAmount),
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
			BalanceDelta: api.Neg(txInfo.AssetAmount),
			LpDelta:      std.ZeroInt,
		},
		// asset gas
		{
			BalanceDelta: api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.GasFeeAssetAmount,
			LpDelta:      std.ZeroInt,
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
			BalanceDelta: api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.GasFeeAssetAmount,
			LpDelta:      std.ZeroInt,
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
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: txInfo.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.ToAccountIndex,
		NftContentHash:      txInfo.NftContentHash,
		NftL1Address:        std.ZeroInt,
		NftL1TokenId:        std.ZeroInt,
		AssetId:             std.ZeroInt,
		AssetAmount:         std.ZeroInt,
		CreatorTreasuryRate: txInfo.CreatorTreasuryRate,
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
			BalanceDelta: api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.GasFeeAssetAmount,
			LpDelta:      std.ZeroInt,
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
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: nftBefore.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.ToAccountIndex,
		NftContentHash:      nftBefore.NftContentHash,
		NftL1Address:        nftBefore.NftL1Address,
		NftL1TokenId:        nftBefore.NftL1TokenId,
		AssetId:             std.ZeroInt,
		AssetAmount:         std.ZeroInt,
		CreatorTreasuryRate: nftBefore.CreatorTreasuryRate,
	}
	return deltas, nftDelta
}

func GetAssetDeltasAndNftDeltaFromSetNftPrice(
	api API,
	txInfo SetNftPriceTxConstraints,
	nftBefore NftConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, nftDelta NftDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.GasFeeAssetAmount,
			LpDelta:      std.ZeroInt,
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
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: nftBefore.CreatorAccountIndex,
		OwnerAccountIndex:   nftBefore.OwnerAccountIndex,
		NftContentHash:      nftBefore.NftContentHash,
		NftL1Address:        nftBefore.NftL1Address,
		NftL1TokenId:        nftBefore.NftL1TokenId,
		AssetId:             txInfo.AssetId,
		AssetAmount:         txInfo.AssetAmount,
		CreatorTreasuryRate: nftBefore.CreatorTreasuryRate,
	}
	return deltas, nftDelta
}

func GetAssetDeltasAndNftDeltaFromBuyNft(
	api API,
	txInfo BuyNftTxConstraints,
	nftBefore NftConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, nftDelta NftDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		// asset A
		{
			BalanceDelta: api.Neg(txInfo.AssetAmount),
			LpDelta:      std.ZeroInt,
		},
		// asset Gas
		{
			BalanceDelta: api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// TODO compute creator treasury and treasury
	creatorTreasuryFee := api.Div(api.Mul(txInfo.AssetAmount, txInfo.CreatorTreasuryRate), 10000)
	treasuryFee := api.Div(api.Mul(txInfo.AssetAmount, txInfo.TreasuryFeeRate), 10000)
	toAccountAssetA := api.Sub(api.Sub(txInfo.AssetAmount, creatorTreasuryFee), treasuryFee)
	// to account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: toAccountAssetA,
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// creator account
	deltas[2] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: creatorTreasuryFee,
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// treasury account
	deltas[3] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: treasuryFee,
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[4] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.GasFeeAssetAmount,
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: nftBefore.CreatorAccountIndex,
		OwnerAccountIndex:   txInfo.BuyerAccountIndex,
		NftContentHash:      nftBefore.NftContentHash,
		NftL1Address:        nftBefore.NftL1Address,
		NftL1TokenId:        nftBefore.NftL1TokenId,
		AssetId:             std.ZeroInt,
		AssetAmount:         std.ZeroInt,
		CreatorTreasuryRate: nftBefore.CreatorTreasuryRate,
	}
	return deltas, nftDelta
}

func GetAssetDeltasAndNftDeltaFromWithdrawNft(
	api API,
	txInfo WithdrawNftTxConstraints,
) (deltas [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints, nftDelta NftDeltaConstraints) {
	// from account
	deltas[0] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: api.Neg(txInfo.GasFeeAssetAmount),
			LpDelta:      std.ZeroInt,
		},
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
		EmptyAccountAssetDeltaConstraints(),
	}
	// gas account
	deltas[1] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
		{
			BalanceDelta: txInfo.GasFeeAssetAmount,
			LpDelta:      std.ZeroInt,
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
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: std.ZeroInt,
		OwnerAccountIndex:   std.ZeroInt,
		NftContentHash:      std.ZeroInt,
		NftL1Address:        std.ZeroInt,
		NftL1TokenId:        std.ZeroInt,
		AssetId:             std.ZeroInt,
		AssetAmount:         std.ZeroInt,
		CreatorTreasuryRate: std.ZeroInt,
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
			BalanceDelta: api.Neg(txInfo.AssetAmount),
			LpDelta:      std.ZeroInt,
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
		AssetId:             std.ZeroInt,
		AssetAmount:         std.ZeroInt,
		CreatorTreasuryRate: std.ZeroInt,
	}
	return nftDelta
}
