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
	"errors"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"
	"log"
)

type AccountConstraints struct {
	AccountIndex      Variable
	AccountName       Variable
	AccountPk         eddsa.PublicKey
	Nonce             Variable
	AccountAssetsRoot Variable
	AccountNftRoot    Variable
	// at most 4 assets changed in one transaction
	AssetsInfo [NbAccountAssetsPerAccount]AccountAssetConstraints
	NftInfo    AccountNftConstraints
}

type AccountAssetConstraints struct {
	Index    Variable
	Balance  Variable
	AssetAId Variable
	AssetBId Variable
	AssetA   Variable
	AssetB   Variable
	LpAmount Variable
}

func SetAccountAssetWitness(asset *AccountAsset) (witness AccountAssetConstraints, err error) {
	if asset == nil {
		log.Println("[SetAccountAssetWitness] invalid params")
		return witness, errors.New("[SetAccountAssetWitness] invalid params")
	}
	witness.Index = asset.Index
	witness.Balance = asset.BalanceEnc
	witness.AssetAId = asset.AssetAId
	witness.AssetBId = asset.AssetBId
	witness.AssetA = asset.AssetA
	witness.AssetB = asset.AssetB
	witness.LpAmount = asset.LpAmount
	return witness, nil
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

func SetAccountNftWitness(nft *AccountNft) (witness AccountNftConstraints, err error) {
	if nft == nil {
		log.Println("[SetAccountNftWitness] invalid params")
		return witness, errors.New("[SetAccountNftWitness] invalid params")
	}
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
	return witness, nil
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
	// set nft witness
	witness.NftInfo, err = SetAccountNftWitness(account.NftInfo)
	if err != nil {
		return witness, err
	}
	// set witness
	witness = AccountConstraints{
		AccountIndex:      account.AccountIndex,
		AccountName:       account.AccountName,
		AccountPk:         std.SetPubKeyWitness(account.AccountPk),
		Nonce:             account.Nonce,
		AccountAssetsRoot: account.AccountAssetsRoot,
		AccountNftRoot:    account.AccountNftRoot,
	}
	return witness, nil
}
