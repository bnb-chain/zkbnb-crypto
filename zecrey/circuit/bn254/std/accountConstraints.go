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
	"github.com/zecrey-labs/zecrey-crypto/zecrey/circuit/bn254/std"
	"log"
)

/*
	AccountConstraints: account constraints
*/
type AccountConstraints struct {
	// account index
	AccountIndex Variable
	// account name
	AccountName Variable
	// account public key
	AccountPk Point
	// account state tree root
	StateRoot Variable
	// assets info for each account per tx
	AssetsInfo [NbAccountAssetsPerAccount]AccountAssetConstraints
	// locked assets info for each account per tx
	LockedAssetInfo AccountAssetLockConstraints
	// liquidity assets info for each account per tx
	LiquidityInfo AccountLiquidityConstraints
	// nft info
	NftInfo AccountNftConstraints

	// account assets root
	AccountAssetsRoot Variable
	// account locked assets root
	AccountLockedAssetsRoot Variable
	// account liquidity root
	AccountLiquidityRoot Variable
	// nft tree root
	AccountNftRoot Variable
}

/*
	AccountAssetConstraints: account asset tree related constraints
*/
type AccountAssetConstraints struct {
	// asset id
	AssetId Variable
	// twisted ElGamal Encryption balance
	BalanceEnc ElGamalEncConstraints
}

/*
	AccountAssetLockConstraints: account locked asset tree related constraints
*/
type AccountAssetLockConstraints struct {
	// chain id
	ChainId Variable
	// asset id
	AssetId Variable
	// locked amount
	LockedAmount Variable
}

/*
	AccountAssetLockConstraints: account liquidity asset tree related constraints
*/
type AccountLiquidityConstraints struct {
	// pair index
	PairIndex Variable
	// asset a id
	AssetAId Variable
	// asset b id
	AssetBId Variable
	// asset a balance
	AssetA Variable
	// asset b balance
	AssetB Variable
	// asset a random value
	AssetAR Variable
	// asset b random value
	AssetBR Variable
	// LP twisted ElGamal encryption
	LpEnc ElGamalEncConstraints
}

/*
	IsAccountLiquidityConstraintsEqual: compare if two AccountLiquidity are the same
*/
func IsAccountLiquidityConstraintsEqual(api API, flag Variable, a, b AccountLiquidityConstraints) {
	std.IsVariableEqual(api, flag, a.AssetA, b.AssetA)
	std.IsVariableEqual(api, flag, a.AssetAR, b.AssetAR)
	std.IsVariableEqual(api, flag, a.AssetB, b.AssetB)
	std.IsVariableEqual(api, flag, a.AssetBR, b.AssetBR)
	std.IsElGamalEncEqual(api, flag, a.LpEnc, b.LpEnc)
}

type AccountNftConstraints struct {
	NftAccountIndex Variable
	NftIndex        Variable
	CreatorIndex    Variable
	NftContentHash  Variable
	AssetId         Variable
	AssetAmount     Variable
	ChainId         Variable
	L1Address       Variable
	L1TokenId       Variable
}

func SetAccountNftWitness(nftInfo *AccountNft) (witness AccountNftConstraints) {
	witness.NftAccountIndex = nftInfo.NftAccountIndex
	witness.NftIndex = nftInfo.NftIndex
	witness.CreatorIndex = nftInfo.CreatorIndex
	witness.NftContentHash = nftInfo.NftContentHash
	witness.AssetId = nftInfo.AssetId
	witness.AssetAmount = nftInfo.AssetAmount
	witness.ChainId = nftInfo.ChainId
	witness.L1Address = nftInfo.L1Address
	witness.L1TokenId = nftInfo.L1TokenId
	return witness
}

/*
	IsAccountNftConstraintsEqual: TODO compare if two IsAccountNftConstraints are the same
*/
func IsAccountNftConstraintsEqual(api API, flag Variable, a, b AccountNftConstraints) {
	std.IsVariableEqual(api, flag, a.NftContentHash, b.NftContentHash)
	std.IsVariableEqual(api, flag, a.AssetId, b.AssetId)
	std.IsVariableEqual(api, flag, a.AssetAmount, b.AssetAmount)
}

/*
	AccountDeltaConstraints: delta balance for each account
*/
type AccountDeltaConstraints struct {
	// assets delta for each asset
	AssetsDeltaInfo [NbAccountAssetsPerAccount]ElGamalEncConstraints
	// locked asset delta
	LockedAssetDeltaInfo Variable
	// liquidity delta info
	LiquidityDeltaInfo AccountLiquidityDeltaConstraints
}

/*
	AccountLiquidityDeltaConstraints: account liquidity asset delta constraints
*/
type AccountLiquidityDeltaConstraints struct {
	AssetADelta  Variable
	AssetBDelta  Variable
	AssetARDelta Variable
	AssetBRDelta Variable
	LpEncDelta   ElGamalEncConstraints
}

/*
	ComputeNewLiquidityConstraints: computation for base + delta
*/
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

/*
	SetAccountWitness: set account circuit witness
*/
func SetAccountWitness(account *Account) (witness AccountConstraints, err error) {
	if account == nil {
		log.Println("[SetAccountWitness] invalid params")
		return witness, errors.New("[SetAccountWitness] invalid params")
	}
	witness.AccountIndex = account.AccountIndex
	witness.AccountName = account.AccountName
	witness.AccountPk, err = std.SetPointWitness(account.AccountPk)
	if err != nil {
		log.Println("[SetAccountWitness] err info:", err)
		return witness, err
	}
	// set root for different trees
	witness.StateRoot = account.StateRoot
	witness.AccountAssetsRoot = account.AccountAssetsRoot
	witness.AccountLockedAssetsRoot = account.AccountLockedAssetsRoot
	witness.AccountLiquidityRoot = account.AccountLiquidityRoot
	witness.AccountNftRoot = account.AccountNftRoot
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
	witness.NftInfo = SetAccountNftWitness(account.NftInfo)
	return witness, nil
}

/*
	SetAccountAssetWitness: set account asset circuit witness
*/
func SetAccountAssetWitness(accountAsset *AccountAsset) (witness AccountAssetConstraints, err error) {
	if accountAsset == nil {
		log.Println("[SetAccountAssetWitness] invalid params")
		return witness, errors.New("[SetAccountAssetWitness] invalid params")
	}
	witness.AssetId = accountAsset.AssetId
	witness.BalanceEnc, err = std.SetElGamalEncWitness(accountAsset.BalanceEnc)
	if err != nil {
		log.Println("[SetAccountAssetWitness] err info:", err)
		return witness, err
	}
	return witness, nil
}

/*
	SetAccountLockedAssetWitness: set account locked asset circuit witness
*/
func SetAccountLockedAssetWitness(accountLockedAsset *AccountAssetLock) (witness AccountAssetLockConstraints, err error) {
	if accountLockedAsset == nil {
		log.Println("[SetAccountLockedAssetWitness] invalid params")
		return witness, errors.New("[SetAccountLockedAssetWitness] invalid params")
	}
	witness.ChainId = accountLockedAsset.ChainId
	witness.AssetId = accountLockedAsset.AssetId
	witness.LockedAmount = accountLockedAsset.LockedAmount
	return witness, nil
}

/*
	SetAccountLiquidityWitness: set account liquidity circuit witness
*/
func SetAccountLiquidityWitness(accountLiquidity *AccountLiquidity) (witness AccountLiquidityConstraints, err error) {
	if accountLiquidity == nil {
		log.Println("[SetAccountLiquidityWitness] invalid params")
		return witness, errors.New("[SetAccountLiquidityWitness] invalid params")
	}
	witness.PairIndex = accountLiquidity.PairIndex
	witness.AssetAId = accountLiquidity.AssetAId
	witness.AssetBId = accountLiquidity.AssetBId
	witness.AssetA = accountLiquidity.AssetA
	witness.AssetAR = accountLiquidity.AssetAR
	witness.AssetB = accountLiquidity.AssetB
	witness.AssetBR = accountLiquidity.AssetBR
	witness.LpEnc, err = std.SetElGamalEncWitness(accountLiquidity.LpEnc)
	if err != nil {
		log.Println("[SetAccountAssetWitness] err info:", err)
		return witness, err
	}
	return witness, nil
}
