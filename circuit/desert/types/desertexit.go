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
	"github.com/bnb-chain/zkbnb-crypto/circuit"
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
	"math/big"
)

type ExitTx struct {
	AccountIndex int64
	L1Address    []byte
	AssetId      int64
	AssetAmount  *big.Int
}

type ExitTxConstraints struct {
	AccountIndex circuit.Variable
	L1Address    circuit.Variable
	AssetId      circuit.Variable
	AssetAmount  circuit.Variable
}

func EmptyExitTxWitness() (witness ExitTxConstraints) {
	return ExitTxConstraints{
		AccountIndex: types.ZeroInt,
		L1Address:    types.ZeroInt,
		AssetId:      types.ZeroInt,
		AssetAmount:  types.ZeroInt,
	}
}

func SetExitTxWitness(tx *ExitTx) (witness ExitTxConstraints) {
	witness = ExitTxConstraints{
		AccountIndex: tx.AccountIndex,
		L1Address:    tx.L1Address,
		AssetId:      tx.AssetId,
		AssetAmount:  tx.AssetAmount,
	}
	return witness
}

func VerifyExitTx(
	api circuit.API, flag types.Variable,
	tx ExitTxConstraints,
	accounts [NbAccountsPerTx]AccountConstraints,
) (pubData [types.PubDataBitsSizePerTx]types.Variable) {
	pubData = CollectPubDataFromExit(api, tx)
	// verify params
	types.IsVariableEqual(api, flag, tx.L1Address, accounts[0].L1Address)
	types.IsVariableEqual(api, flag, tx.AccountIndex, accounts[0].AccountIndex)
	types.IsVariableEqual(api, flag, tx.AssetId, accounts[0].AssetsInfo.AssetId)
	types.IsVariableEqual(api, flag, tx.AssetAmount, accounts[0].AssetsInfo.Balance)
	return pubData
}

func VerifyDeltaExitTx(api circuit.API, flag circuit.Variable, tx ExitTxConstraints) {
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.AccountIndex), tx.AccountIndex)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.AssetId), tx.AssetId)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.AssetAmount), tx.AssetAmount)
	api.AssertIsEqual(api.Select(api.Sub(1, flag), types.ZeroInt, tx.L1Address), tx.L1Address)
}
