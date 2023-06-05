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
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
	"log"

	"github.com/consensys/gnark/std/signature/eddsa"
)

type AccountConstraints struct {
	AccountIndex    types.Variable
	L1Address       types.Variable
	AccountPk       eddsa.PublicKey
	Nonce           types.Variable
	CollectionNonce types.Variable
	AssetRoot       types.Variable
	AssetsInfo      types.AccountAssetConstraints
}

func CheckEmptyAccountNode(api types.API, flag types.Variable, account AccountConstraints) {
	types.IsVariableEqual(api, flag, account.L1Address, types.ZeroInt)
	types.IsVariableEqual(api, flag, account.AccountPk.A.X, types.ZeroInt)
	types.IsVariableEqual(api, flag, account.AccountPk.A.Y, types.ZeroInt)
	types.IsVariableEqual(api, flag, account.Nonce, types.ZeroInt)
	types.IsVariableEqual(api, flag, account.CollectionNonce, types.ZeroInt)
	// empty asset

	types.IsVariableEqual(api, flag, account.AssetRoot, types.EmptyAssetRoot)
}

func CheckNonEmptyAccountNode(api types.API, flag types.Variable, account AccountConstraints) {
	types.IsVariableDifferent(api, flag, account.L1Address, types.ZeroInt)
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
		AccountPk:       types.SetPubKeyWitness(account.AccountPk),
		Nonce:           account.Nonce,
		CollectionNonce: account.CollectionNonce,
		AssetRoot:       account.AssetRoot,
	}
	// set assets witness
	witness.AssetsInfo, err = types.SetAccountAssetWitness(account.AssetsInfo)
	if err != nil {
		return witness, err
	}
	return witness, nil
}
