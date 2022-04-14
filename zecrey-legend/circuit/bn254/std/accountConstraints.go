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

import (
	"errors"
	"github.com/consensys/gnark/std/signature/eddsa"
	"log"
)

type AccountConstraints struct {
	AccountIndex         Variable
	AccountName          Variable
	AccountPk            eddsa.PublicKey
	Nonce                Variable
	AccountAssetsRoot    Variable
	AccountLiquidityRoot Variable
	AccountNftRoot       Variable
	// at most 4 assets changed in one transaction
	AssetsInfo    [NbAccountAssetsPerAccount]AccountAssetConstraints
	LiquidityInfo AccountLiquidityConstraints
	NftInfo       AccountNftConstraints
}

func CompareAccountsAfterUpdate(api API, oAccounts, nAccounts [NbAccountsPerTx]AccountConstraints) {
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			api.AssertIsEqual(oAccounts[i].AssetsInfo[j].Balance, nAccounts[i].AssetsInfo[j].Balance)
		}
		api.AssertIsEqual(oAccounts[i].LiquidityInfo.AssetAAmount, nAccounts[i].LiquidityInfo.AssetAAmount)
		api.AssertIsEqual(oAccounts[i].LiquidityInfo.AssetBAmount, nAccounts[i].LiquidityInfo.AssetBAmount)
		api.AssertIsEqual(oAccounts[i].LiquidityInfo.LpAmount, nAccounts[i].LiquidityInfo.LpAmount)
	}
}

type AccountAssetConstraints struct {
	AssetId Variable
	Balance Variable
}

func SetAccountAssetWitness(asset *AccountAsset) (witness AccountAssetConstraints, err error) {
	if asset == nil {
		log.Println("[SetAccountAssetWitness] invalid params")
		return witness, errors.New("[SetAccountAssetWitness] invalid params")
	}
	witness.AssetId = asset.AssetId
	witness.Balance = asset.Balance
	return witness, nil
}

type AccountLiquidityConstraints struct {
	PairIndex    Variable
	AssetAId     Variable
	AssetAAmount Variable
	AssetBId     Variable
	AssetBAmount Variable
	LpAmount     Variable
}

func SetAccountLiquidityWitness(info *AccountLiquidity) (witness AccountLiquidityConstraints) {
	witness = AccountLiquidityConstraints{
		PairIndex:    info.PairIndex,
		AssetAId:     info.AssetAId,
		AssetAAmount: info.AssetAAmount,
		AssetBId:     info.AssetBId,
		AssetBAmount: info.AssetBAmount,
		LpAmount:     info.LpAmount,
	}
	return witness
}

type AccountNftConstraints struct {
	NftIndex       Variable
	CreatorIndex   Variable
	NftContentHash Variable
	AssetId        Variable
	AssetAmount    Variable
	ChainId        Variable
	L1Address      Variable
	L1TokenId      Variable
}

func SetAccountNftWitness(nft *AccountNft) (witness AccountNftConstraints) {
	witness = AccountNftConstraints{
		NftIndex:       nft.NftIndex,
		CreatorIndex:   nft.CreatorIndex,
		NftContentHash: nft.NftContentHash,
		AssetId:        nft.AssetId,
		AssetAmount:    nft.AssetAmount,
		ChainId:        nft.ChainId,
		L1Address:      nft.L1Address,
		L1TokenId:      nft.L1TokenId,
	}
	return witness
}

/*
	SetAccountWitness: set account witness
*/
func SetAccountWitness(account *Account) (witness AccountConstraints, err error) {
	if account == nil {
		log.Println("[SetAccountConstraints] invalid params")
		return witness, errors.New("[SetAccountConstraints] invalid params")
	}
	// set assets witness
	for i := 0; i < NbAccountAssetsPerAccount; i++ {
		witness.AssetsInfo[i], err = SetAccountAssetWitness(account.AssetsInfo[i])
		if err != nil {
			return witness, err
		}
	}
	// set liquidity witness
	witness.LiquidityInfo = SetAccountLiquidityWitness(account.LiquidityInfo)
	// set nft witness
	witness.NftInfo = SetAccountNftWitness(account.NftInfo)
	// set witness
	witness = AccountConstraints{
		AccountIndex:         account.AccountIndex,
		AccountName:          account.AccountName,
		AccountPk:            SetPubKeyWitness(account.AccountPk),
		Nonce:                account.Nonce,
		AccountAssetsRoot:    account.AccountAssetsRoot,
		AccountLiquidityRoot: account.AccountLiquidityRoot,
		AccountNftRoot:       account.AccountNftRoot,
	}
	return witness, nil
}
