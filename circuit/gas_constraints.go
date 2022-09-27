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

package circuit

import (
	"errors"
	"log"

	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type GasAccountConstraints struct {
	AccountIndex    Variable
	AccountNameHash Variable
	AccountPk       eddsa.PublicKey
	Nonce           Variable
	CollectionNonce Variable
	AssetRoot       Variable
	AssetsInfo      []types.AccountAssetConstraints
	GasAssetCount   int
}

type GasConstraints struct {
	GasAssetCount                   int
	AccountInfoBefore               GasAccountConstraints
	MerkleProofsAccountBefore       [AccountMerkleLevels]Variable
	MerkleProofsAccountAssetsBefore [][AssetMerkleLevels]Variable
}

func VerifyGas(
	api API,
	gas GasConstraints,
	gasAssetDeltas []Variable,
	hFunc MiMC,
	lastRoots [types.NbRoots]Variable) (newStateRoot Variable, err error) {
	isEmpty := api.IsZero(api.Sub(gas.AccountInfoBefore.AccountIndex, LastAccountIndex))
	notEmpty := api.IsZero(isEmpty)
	NewAccountRoot := lastRoots[0]
	var (
		NewAccountAssetsRoot = gas.AccountInfoBefore.AssetRoot
	)

	gasAssetCount := len(gasAssetDeltas)
	deltas := make([]AccountAssetDeltaConstraints, gasAssetCount)

	for i := 0; i < gasAssetCount; i++ {
		deltas[i] = AccountAssetDeltaConstraints{
			BalanceDelta:             gasAssetDeltas[i],
			LpDelta:                  types.ZeroInt,
			OfferCanceledOrFinalized: types.ZeroInt,
		}
	}
	AccountsInfoAfter := UpdateGasAccount(api, gas.AccountInfoBefore, gasAssetCount, deltas)

	// verify account asset node hash
	for i := 0; i < gasAssetCount; i++ {
		assetMerkleHelper := AssetIdToMerkleHelper(api, gas.AccountInfoBefore.AssetsInfo[i].AssetId)
		hFunc.Reset()
		hFunc.Write(
			gas.AccountInfoBefore.AssetsInfo[i].Balance,
			types.ZeroInt,
			types.ZeroInt,
		)
		assetNodeHash := hFunc.Sum()
		// verify account asset merkle proof
		hFunc.Reset()
		types.VerifyMerkleProof(
			api,
			notEmpty,
			hFunc,
			NewAccountAssetsRoot,
			assetNodeHash,
			gas.MerkleProofsAccountAssetsBefore[i][:],
			assetMerkleHelper,
		)
		hFunc.Reset()
		hFunc.Write(
			AccountsInfoAfter.AssetsInfo[i].Balance,
			types.ZeroInt,
			types.ZeroInt,
		)
		assetNodeHash = hFunc.Sum()
		hFunc.Reset()
		// update merkle proof
		NewAccountAssetsRoot = types.UpdateMerkleProof(
			api, hFunc, assetNodeHash, gas.MerkleProofsAccountAssetsBefore[i][:], assetMerkleHelper)
	}
	// verify account node hash
	accountIndexMerkleHelper := AccountIndexToMerkleHelper(api, gas.AccountInfoBefore.AccountIndex)
	hFunc.Reset()
	hFunc.Write(
		gas.AccountInfoBefore.AccountNameHash,
		gas.AccountInfoBefore.AccountPk.A.X,
		gas.AccountInfoBefore.AccountPk.A.Y,
		gas.AccountInfoBefore.Nonce,
		gas.AccountInfoBefore.CollectionNonce,
		gas.AccountInfoBefore.AssetRoot,
	)
	accountNodeHash := hFunc.Sum()
	// verify account merkle proof
	hFunc.Reset()
	types.VerifyMerkleProof(
		api,
		notEmpty,
		hFunc,
		NewAccountRoot,
		accountNodeHash,
		gas.MerkleProofsAccountBefore[:],
		accountIndexMerkleHelper,
	)
	hFunc.Reset()
	hFunc.Write(
		AccountsInfoAfter.AccountNameHash,
		AccountsInfoAfter.AccountPk.A.X,
		AccountsInfoAfter.AccountPk.A.Y,
		AccountsInfoAfter.Nonce,
		AccountsInfoAfter.CollectionNonce,
		NewAccountAssetsRoot,
	)
	accountNodeHash = hFunc.Sum()
	hFunc.Reset()
	// update merkle proof
	NewAccountRoot = types.UpdateMerkleProof(api, hFunc, accountNodeHash, gas.MerkleProofsAccountBefore[:], accountIndexMerkleHelper)

	hFunc.Reset()
	hFunc.Write(
		NewAccountRoot,
		lastRoots[1],
		lastRoots[2],
	)
	newStateRoot = hFunc.Sum()
	return newStateRoot, err
}

func UpdateGasAccount(
	api API,
	accountInfo GasAccountConstraints,
	gasAssetCount int,
	gasAssetsDeltas []AccountAssetDeltaConstraints,
) (accountInfoAfter GasAccountConstraints) {
	accountInfoAfter = accountInfo
	for i := 0; i < gasAssetCount; i++ {
		accountInfoAfter.AssetsInfo[i].Balance = api.Add(
			accountInfo.AssetsInfo[i].Balance,
			gasAssetsDeltas[i].BalanceDelta)
	}
	return accountInfoAfter
}

func GetZeroGasConstraints(gasAssetCount int) GasConstraints {
	var zeroGasConstraint GasConstraints
	zeroGasConstraint.GasAssetCount = gasAssetCount

	// set witness
	zeroAccountConstraint := GasAccountConstraints{
		AccountIndex:    0,
		AccountNameHash: 0,
		AccountPk:       types.EmptyPublicKeyWitness(),
		Nonce:           0,
		CollectionNonce: 0,
		AssetRoot:       0,
		GasAssetCount:   gasAssetCount,
	}
	zeroAccountConstraint.AssetsInfo = make([]types.AccountAssetConstraints, gasAssetCount)
	// set assets witness
	for i := 0; i < gasAssetCount; i++ {
		zeroAccountConstraint.AssetsInfo[i] = types.AccountAssetConstraints{
			AssetId: 0,
			Balance: 0,
		}
	}
	// accounts info before
	zeroGasConstraint.AccountInfoBefore = zeroAccountConstraint
	zeroGasConstraint.MerkleProofsAccountAssetsBefore = make([][AssetMerkleLevels]Variable, gasAssetCount)
	for j := 0; j < gasAssetCount; j++ {
		for k := 0; k < AssetMerkleLevels; k++ {
			// account assets before
			zeroGasConstraint.MerkleProofsAccountAssetsBefore[j][k] = 0
		}
	}
	for j := 0; j < AccountMerkleLevels; j++ {
		// account before
		zeroGasConstraint.MerkleProofsAccountBefore[j] = 0
	}

	return zeroGasConstraint
}

func SetGasAccountWitness(account *types.GasAccount, assetCount int) (witness GasAccountConstraints, err error) {
	if account == nil {
		log.Println("[SetAccountConstraints] invalid params")
		return witness, errors.New("[SetAccountConstraints] invalid params")
	}
	// set witness
	witness = GasAccountConstraints{
		AccountIndex:    account.AccountIndex,
		AccountNameHash: account.AccountNameHash,
		AccountPk:       types.SetPubKeyWitness(account.AccountPk),
		Nonce:           account.Nonce,
		CollectionNonce: account.CollectionNonce,
		AssetRoot:       account.AssetRoot,
		AssetsInfo:      make([]types.AccountAssetConstraints, 0, 2),
	}
	// set assets witness
	for i := 0; i < assetCount; i++ {
		assetInfo, err := types.SetAccountAssetWitness(account.AssetsInfo[i])
		if err != nil {
			return witness, err
		}
		witness.AssetsInfo = append(witness.AssetsInfo, assetInfo)
	}
	return witness, nil
}

func SetGasWitness(oGas *Gas) (witness GasConstraints, err error) {
	witness.GasAssetCount = oGas.GasAssetCount
	witness.AccountInfoBefore, err = SetGasAccountWitness(oGas.AccountInfoBefore, oGas.GasAssetCount)
	if err != nil {
		log.Println("fail to set gas witness, err:", err.Error())
		return witness, err
	}
	for i := 0; i < AccountMerkleLevels; i++ {
		// account before
		witness.MerkleProofsAccountBefore[i] = oGas.MerkleProofsAccountBefore[i]
	}
	witness.MerkleProofsAccountAssetsBefore = make([][AssetMerkleLevels]Variable, 0)
	for i := 0; i < oGas.GasAssetCount; i++ {
		merkleProofsAccountAssets := [AssetMerkleLevels]Variable{}
		for j := 0; j < AssetMerkleLevels; j++ {
			// account assets before
			merkleProofsAccountAssets[j] = oGas.MerkleProofsAccountAssetsBefore[i][j]
		}
		witness.MerkleProofsAccountAssetsBefore = append(witness.MerkleProofsAccountAssetsBefore, merkleProofsAccountAssets)
	}
	return witness, nil
}
