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
	"math/big"
)

type FullExitTx struct {
	AccountIndex int64
	L1Address    []byte
	AssetId      int64
	AssetAmount  *big.Int
}

type FullExitTxConstraints struct {
	AccountIndex Variable
	L1Address    Variable
	AssetId      Variable
	AssetAmount  Variable
}

func EmptyFullExitTxWitness() (witness FullExitTxConstraints) {
	return FullExitTxConstraints{
		AccountIndex: ZeroInt,
		L1Address:    ZeroInt,
		AssetId:      ZeroInt,
		AssetAmount:  ZeroInt,
	}
}

func SetFullExitTxWitness(tx *FullExitTx) (witness FullExitTxConstraints) {
	witness = FullExitTxConstraints{
		AccountIndex: tx.AccountIndex,
		L1Address:    tx.L1Address,
		AssetId:      tx.AssetId,
		AssetAmount:  tx.AssetAmount,
	}
	return witness
}

func VerifyFullExitTx(
	api API, flag Variable,
	tx FullExitTxConstraints,
	accountsBefore [NbAccountsPerTx]AccountConstraints,
) (pubData [PubDataBitsSizePerTx]Variable) {
	txInfoL1Address := api.Select(flag, tx.L1Address, ZeroInt)
	beforeL1Address := api.Select(flag, accountsBefore[0].L1Address, ZeroInt)
	isOwner := api.And(api.IsZero(api.Cmp(txInfoL1Address, beforeL1Address)), flag)
	tx.AssetAmount = api.Select(isOwner, tx.AssetAmount, ZeroInt)
	pubData = CollectPubDataFromFullExit(api, tx)
	// verify params
	IsVariableEqual(api, isOwner, tx.L1Address, accountsBefore[0].L1Address)
	IsVariableEqual(api, flag, tx.AccountIndex, accountsBefore[0].AccountIndex)
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[0].AssetsInfo[0].AssetId)

	IsVariableEqual(api, isOwner, tx.AssetAmount, accountsBefore[0].AssetsInfo[0].Balance)
	return pubData
}

func VerifyDeltaFullExitTx(api API, flag Variable, tx FullExitTxConstraints) {
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.AccountIndex), tx.AccountIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.AssetId), tx.AssetId)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.AssetAmount), tx.AssetAmount)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), ZeroInt, tx.L1Address), tx.L1Address)
}
