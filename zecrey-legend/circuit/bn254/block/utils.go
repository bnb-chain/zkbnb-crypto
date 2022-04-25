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

import "github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"

func CompareAccountBeforeAndAfterParams(api API, accountBefore, accountAfter std.AccountConstraints) {
	/*
		AccountIndex      Variable
		AccountName       Variable
		AccountPk         eddsa.PublicKey
		Nonce             Variable
	*/
	// basic info
	api.AssertIsEqual(accountBefore.AccountIndex, accountAfter.AccountIndex)
	api.AssertIsEqual(accountBefore.AccountName, accountAfter.AccountName)
	std.IsEqualPubKey(api, accountBefore.AccountPk, accountAfter.AccountPk)
	updatedNonce := api.Add(accountBefore.Nonce, 1)
	api.AssertIsEqual(updatedNonce, accountAfter.Nonce)
	// account assets basic info
	/*
		AssetId    Variable
		Balance  Variable
	*/
	for i := 0; i < NbAccountAssetsPerAccount; i++ {
		api.AssertIsEqual(accountBefore.AssetsInfo[i].AssetId, accountAfter.AssetsInfo[i].AssetId)
	}
	// account liquidity basic info
	api.AssertIsEqual(accountBefore.LiquidityInfo.AssetAId, accountAfter.LiquidityInfo.AssetAId)
	api.AssertIsEqual(accountBefore.LiquidityInfo.AssetBId, accountAfter.LiquidityInfo.AssetBId)
	// account nft basic info
	/*
		NftIndex       Variable
		CreatorIndex   Variable
		NftContentHash Variable
		AssetId        Variable
		AssetAmount    Variable
		NftL1Address      Variable
		NftL1TokenId      Variable
	*/
	api.AssertIsEqual(accountBefore.NftInfo.NftAssetId, accountAfter.NftInfo.NftAssetId)
	api.AssertIsEqual(accountBefore.NftInfo.NftL1Address, accountAfter.NftInfo.NftL1Address)
	api.AssertIsEqual(accountBefore.NftInfo.NftL1TokenId, accountAfter.NftInfo.NftL1TokenId)
}

func SelectDeltas(
	api API,
	flag Variable,
	deltas, deltasCheck [NbAccountsPerTx]AccountDeltaConstraints,
) (deltasRes [NbAccountsPerTx]AccountDeltaConstraints) {
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			deltasRes[i].AssetDeltas[j] =
				api.Select(flag, deltas[i].AssetDeltas[j], deltasCheck[i].AssetDeltas[j])
		}
		deltasRes[i].LiquidityDelta.AssetADelta =
			api.Select(flag, deltas[i].LiquidityDelta.AssetADelta, deltasCheck[i].LiquidityDelta.AssetADelta)
		deltasRes[i].LiquidityDelta.AssetBDelta =
			api.Select(flag, deltas[i].LiquidityDelta.AssetBDelta, deltasCheck[i].LiquidityDelta.AssetBDelta)
		deltasRes[i].LiquidityDelta.LpDelta =
			api.Select(flag, deltas[i].LiquidityDelta.LpDelta, deltasCheck[i].LiquidityDelta.LpDelta)
	}
	return deltasRes
}

func SelectNftDeltas(
	api API,
	flag Variable,
	deltas, deltasCheck [NbAccountsPerTx]AccountNftDeltaConstraints,
) (deltasRes [NbAccountsPerTx]AccountNftDeltaConstraints) {
	for i := 0; i < NbAccountsPerTx; i++ {
		deltasRes[i].NftIndex =
			api.Select(flag, deltas[i].NftIndex, deltasCheck[i].NftIndex)
		deltasRes[i].NftAssetId =
			api.Select(flag, deltas[i].NftAssetId, deltasCheck[i].NftAssetId)
		deltasRes[i].NftContentHash =
			api.Select(flag, deltas[i].NftContentHash, deltasCheck[i].NftContentHash)
		deltasRes[i].AssetId =
			api.Select(flag, deltas[i].AssetId, deltasCheck[i].AssetId)
		deltasRes[i].AssetAmount =
			api.Select(flag, deltas[i].AssetAmount, deltasCheck[i].AssetAmount)
		deltasRes[i].NftL1TokenId =
			api.Select(flag, deltas[i].NftL1TokenId, deltasCheck[i].NftL1TokenId)
		deltasRes[i].NftL1Address =
			api.Select(flag, deltas[i].NftL1Address, deltasCheck[i].NftL1Address)
	}
	return deltasRes
}
