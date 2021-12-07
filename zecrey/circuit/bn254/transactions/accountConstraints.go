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

package transactions

import (
	"errors"
	"log"
	"zecrey-crypto/zecrey/circuit/bn254/std"
)

type AccountConstraints struct {
	AccountIndex            Variable
	AccountName             Variable
	AccountPk               Point
	StateRoot               Variable
	AssetsInfo              [NbAccountAssetsPerAccount]AccountAssetConstraints
	LockedAssetInfo         AccountAssetLockConstraints
	LiquidityInfo           AccountLiquidityConstraints
	AccountAssetsRoot       Variable
	AccountLockedAssetsRoot Variable
	AccountLiquidityRoot    Variable
}

type AccountAssetConstraints struct {
	AssetId    Variable
	BalanceEnc ElGamalEncConstraints
}

type AccountAssetLockConstraints struct {
	ChainId      Variable
	AssetId      Variable
	LockedAmount Variable
}

type AccountLiquidityConstraints struct {
	PairIndex Variable
	AssetAId  Variable
	AssetBId  Variable
	AssetA    Variable
	AssetB    Variable
	AssetAR   Variable
	AssetBR   Variable
	LpEnc     ElGamalEncConstraints
}

func IsAccountLiquidityConstraintsEqual(api API, flag Variable, a, b AccountLiquidityConstraints) {
	std.IsVariableEqual(api, flag, a.AssetA, b.AssetA)
	std.IsVariableEqual(api, flag, a.AssetAR, b.AssetAR)
	std.IsVariableEqual(api, flag, a.AssetB, b.AssetB)
	std.IsVariableEqual(api, flag, a.AssetBR, b.AssetBR)
	std.IsElGamalEncEqual(api, flag, a.LpEnc, b.LpEnc)
}

type AccountDeltaConstraints struct {
	AssetsDeltaInfo      [NbAccountAssetsPerAccount]ElGamalEncConstraints
	LockedAssetDeltaInfo Variable
	LiquidityDeltaInfo   AccountLiquidityDeltaConstraints
}

type AccountLiquidityDeltaConstraints struct {
	AssetADelta  Variable
	AssetBDelta  Variable
	AssetARDelta Variable
	AssetBRDelta Variable
	LpEncDelta   ElGamalEncConstraints
}

func ComputeNewLiquidityConstraints(api API, tool *EccTool, balance AccountLiquidityConstraints, delta AccountLiquidityDeltaConstraints) (newBalance AccountLiquidityConstraints) {
	newBalance.AssetAId = balance.AssetAId
	newBalance.AssetBId = balance.AssetBId
	newBalance.PairIndex = balance.PairIndex
	newBalance.AssetA = api.Add(balance.AssetA, delta.AssetADelta)
	newBalance.AssetAR = api.Add(balance.AssetAR, delta.AssetARDelta)
	newBalance.AssetB = api.Add(balance.AssetB, delta.AssetBDelta)
	newBalance.AssetBR = api.Add(balance.AssetBR, delta.AssetBRDelta)
	newBalance.LpEnc = tool.EncAdd(balance.LpEnc, delta.LpEncDelta)
	return newBalance
}

func SetAccountWitness(account *Account) (witness AccountConstraints, err error) {
	if account == nil {
		log.Println("[SetAccountWitness] invalid params")
		return witness, errors.New("[SetAccountWitness] invalid params")
	}
	witness.AccountIndex.Assign(account.AccountIndex)
	witness.AccountName.Assign(account.AccountName)
	witness.AccountPk, err = std.SetPointWitness(account.AccountPk)
	if err != nil {
		log.Println("[SetAccountWitness] err info:", err)
		return witness, err
	}
	// set root for different trees
	witness.StateRoot.Assign(account.StateRoot)
	witness.AccountAssetsRoot.Assign(account.AccountAssetsRoot)
	witness.AccountLockedAssetsRoot.Assign(account.AccountLockedAssetsRoot)
	witness.AccountLiquidityRoot.Assign(account.AccountLiquidityRoot)
	// set asset info
	for i, asset := range account.AssetsInfo {
		witness.AssetsInfo[i], err = SetAccountAssetWitness(asset)
		if err != nil {
			log.Println("[SetAccountWitness] err info:", err)
			return witness, err
		}
	}
	// set locked asset info
	witness.LockedAssetInfo, err = SetAccountLockedAssetWitness(account.LockedAssetInfo)
	if err != nil {
		log.Println("[SetAccountWitness] err info:", err)
		return witness, err
	}
	// set liquidity info
	witness.LiquidityInfo, err = SetAccountLiquidityWitness(account.LiquidityInfo)
	if err != nil {
		log.Println("[SetAccountWitness] err info:", err)
		return witness, err
	}
	return witness, nil
}

func SetAccountAssetWitness(accountAsset *AccountAsset) (witness AccountAssetConstraints, err error) {
	if accountAsset == nil {
		log.Println("[SetAccountAssetWitness] invalid params")
		return witness, errors.New("[SetAccountAssetWitness] invalid params")
	}
	witness.AssetId.Assign(accountAsset.AssetId)
	witness.BalanceEnc, err = std.SetElGamalEncWitness(accountAsset.BalanceEnc)
	if err != nil {
		log.Println("[SetAccountAssetWitness] err info:", err)
		return witness, err
	}
	return witness, nil
}

func SetAccountLockedAssetWitness(accountLockedAsset *AccountAssetLock) (witness AccountAssetLockConstraints, err error) {
	if accountLockedAsset == nil {
		log.Println("[SetAccountLockedAssetWitness] invalid params")
		return witness, errors.New("[SetAccountLockedAssetWitness] invalid params")
	}
	witness.ChainId.Assign(accountLockedAsset.ChainId)
	witness.AssetId.Assign(accountLockedAsset.AssetId)
	witness.LockedAmount.Assign(accountLockedAsset.LockedAmount)
	return witness, nil
}

func SetAccountLiquidityWitness(accountLiquidity *AccountLiquidity) (witness AccountLiquidityConstraints, err error) {
	if accountLiquidity == nil {
		log.Println("[SetAccountLiquidityWitness] invalid params")
		return witness, errors.New("[SetAccountLiquidityWitness] invalid params")
	}
	witness.PairIndex.Assign(accountLiquidity.PairIndex)
	witness.AssetAId.Assign(accountLiquidity.AssetAId)
	witness.AssetBId.Assign(accountLiquidity.AssetBId)
	witness.AssetA.Assign(accountLiquidity.AssetA)
	witness.AssetAR.Assign(accountLiquidity.AssetAR)
	witness.AssetB.Assign(accountLiquidity.AssetB)
	witness.AssetBR.Assign(accountLiquidity.AssetBR)
	witness.LpEnc, err = std.SetElGamalEncWitness(accountLiquidity.LpEnc)
	if err != nil {
		log.Println("[SetAccountAssetWitness] err info:", err)
		return witness, err
	}
	return witness, nil
}
