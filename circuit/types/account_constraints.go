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

import (
	"errors"
	"log"

	"github.com/consensys/gnark/std/signature/eddsa"
)

type AccountConstraints struct {
	AccountIndex    Variable
	L1Address       Variable
	AccountPk       eddsa.PublicKey
	Nonce           Variable
	CollectionNonce Variable
	AssetRoot       Variable
	// at most 4 assets changed in one transaction
	AssetsInfo [NbAccountAssetsPerAccount]AccountAssetConstraints
}

func CheckEmptyAccountNode(api API, flag Variable, account AccountConstraints) {
	IsVariableEqual(api, flag, account.L1Address, ZeroInt)
	IsVariableEqual(api, flag, account.AccountPk.A.X, ZeroInt)
	IsVariableEqual(api, flag, account.AccountPk.A.Y, ZeroInt)
	IsVariableEqual(api, flag, account.Nonce, ZeroInt)
	IsVariableEqual(api, flag, account.CollectionNonce, ZeroInt)
	// empty asset
	IsVariableEqual(api, flag, account.AssetRoot, EmptyAssetRoot)
}

func CheckNonEmptyAccountNode(api API, flag Variable, account AccountConstraints) {
	IsVariableDifferent(api, flag, account.L1Address, ZeroInt)
}

type AccountAssetConstraints struct {
	AssetId                  Variable
	Balance                  Variable
	OfferCanceledOrFinalized Variable
}

func SetAccountAssetWitness(asset *AccountAsset) (witness AccountAssetConstraints, err error) {
	if asset == nil {
		log.Println("[SetAccountAssetWitness] invalid params")
		return witness, errors.New("[SetAccountAssetWitness] invalid params")
	}
	witness = AccountAssetConstraints{
		AssetId:                  asset.AssetId,
		Balance:                  asset.Balance,
		OfferCanceledOrFinalized: asset.OfferCanceledOrFinalized,
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
	// set witness
	witness = AccountConstraints{
		AccountIndex:    account.AccountIndex,
		L1Address:       account.L1Address,
		AccountPk:       SetPubKeyWitness(account.AccountPk),
		Nonce:           account.Nonce,
		CollectionNonce: account.CollectionNonce,
		AssetRoot:       account.AssetRoot,
	}
	// set assets witness
	for i := 0; i < NbAccountAssetsPerAccount; i++ {
		witness.AssetsInfo[i], err = SetAccountAssetWitness(account.AssetsInfo[i])
		if err != nil {
			return witness, err
		}
	}
	return witness, nil
}
