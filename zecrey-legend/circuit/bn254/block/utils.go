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
		ChainId        Variable
		L1Address      Variable
		L1TokenId      Variable
	*/
	api.AssertIsEqual(accountBefore.NftInfo.ChainId, accountAfter.NftInfo.ChainId)
	api.AssertIsEqual(accountBefore.NftInfo.L1Address, accountAfter.NftInfo.L1Address)
	api.AssertIsEqual(accountBefore.NftInfo.L1TokenId, accountAfter.NftInfo.L1TokenId)
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
