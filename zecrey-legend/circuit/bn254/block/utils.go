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

func CompareAccountBeforeAndAfterParams(api API, accountBefore, accountAfter AccountConstraints) {
	/*
		AccountIndex      Variable
		AccountName       Variable
		AccountPk         eddsa.PublicKey
		Nonce             Variable
		StateRoot         Variable
		AccountAssetsRoot Variable
		AccountNftRoot    Variable
		// at most 4 assets changed in one transaction
		AssetsInfo [NbAccountAssetsPerAccount]AccountAssetConstraints
		NftInfo    AccountNftConstraints
	*/
	// basic info
	api.AssertIsEqual(accountBefore.AccountIndex, accountAfter.AccountIndex)
	api.AssertIsEqual(accountBefore.AccountName, accountAfter.AccountName)
	std.IsEqualPubKey(api, accountBefore.AccountPk, accountAfter.AccountPk)
	updatedNonce := api.Add(accountBefore.Nonce, 1)
	api.AssertIsEqual(updatedNonce, accountAfter.Nonce)
	// account assets basic info
	/*
		Index    Variable
		Balance  Variable
		AssetAId Variable
		AssetBId Variable
		AssetA   Variable
		AssetB   Variable
		LpAmount Variable
	*/
	for i := 0; i < NbAccountAssetsPerAccount; i++ {
		api.AssertIsEqual(accountBefore.AssetsInfo[i].Index, accountAfter.AssetsInfo[i].Index)
		api.AssertIsEqual(accountBefore.AssetsInfo[i].AssetAId, accountAfter.AssetsInfo[i].AssetAId)
		api.AssertIsEqual(accountBefore.AssetsInfo[i].AssetBId, accountAfter.AssetsInfo[i].AssetBId)
	}
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
