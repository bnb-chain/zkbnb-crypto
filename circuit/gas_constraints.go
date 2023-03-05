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
	"github.com/consensys/gnark/std/hash/poseidon"
	"log"

	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type GasAccountConstraints struct {
	AccountIndex    Variable
	L1Address       Variable
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
	needGas Variable,
	gasAssetDeltas []Variable,
	accountRoot Variable) (newAccountRoot Variable, err error) {
	newAccountRoot = accountRoot
	newAccountAssetsRoot := gas.AccountInfoBefore.AssetRoot

	// check the existence of gas account
	types.IsVariableDifferent(api, needGas, gas.AccountInfoBefore.L1Address, types.ZeroInt)

	gasAssetCount := len(gasAssetDeltas)
	for i := 0; i < gasAssetCount; i++ {
		assetMerkleHelper := AssetIdToMerkleHelper(api, gas.AccountInfoBefore.AssetsInfo[i].AssetId)
		assetNodeHash := poseidon.Poseidon(api,
			gas.AccountInfoBefore.AssetsInfo[i].Balance,
			gas.AccountInfoBefore.AssetsInfo[i].OfferCanceledOrFinalized)
		types.VerifyMerkleProof(
			api,
			needGas,
			newAccountAssetsRoot,
			assetNodeHash,
			gas.MerkleProofsAccountAssetsBefore[i][:],
			assetMerkleHelper,
		)
		assetNodeHash = poseidon.Poseidon(api,
			api.Add(gas.AccountInfoBefore.AssetsInfo[i].Balance, gasAssetDeltas[i]),
			gas.AccountInfoBefore.AssetsInfo[i].OfferCanceledOrFinalized)
		newAccountAssetsRoot = types.UpdateMerkleProof(
			api, assetNodeHash, gas.MerkleProofsAccountAssetsBefore[i][:], assetMerkleHelper)
	}
	// verify account node hash
	accountIndexMerkleHelper := AccountIndexToMerkleHelper(api, gas.AccountInfoBefore.AccountIndex)
	accountNodeHash := poseidon.Poseidon(api,
		gas.AccountInfoBefore.L1Address,
		gas.AccountInfoBefore.AccountPk.A.X,
		gas.AccountInfoBefore.AccountPk.A.Y,
		gas.AccountInfoBefore.Nonce,
		gas.AccountInfoBefore.CollectionNonce,
		gas.AccountInfoBefore.AssetRoot)
	// verify account merkle proof
	types.VerifyMerkleProof(
		api,
		needGas,
		newAccountRoot,
		accountNodeHash,
		gas.MerkleProofsAccountBefore[:],
		accountIndexMerkleHelper,
	)
	accountNodeHash = poseidon.Poseidon(api,
		gas.AccountInfoBefore.L1Address,
		gas.AccountInfoBefore.AccountPk.A.X,
		gas.AccountInfoBefore.AccountPk.A.Y,
		gas.AccountInfoBefore.Nonce,
		gas.AccountInfoBefore.CollectionNonce,
		newAccountAssetsRoot)
	// update merkle proof
	newAccountRoot = types.UpdateMerkleProof(api, accountNodeHash, gas.MerkleProofsAccountBefore[:], accountIndexMerkleHelper)
	return newAccountRoot, err
}

func GetZeroGasConstraints(gasAssets []int64) GasConstraints {
	gasAssetCount := len(gasAssets)
	var zeroGasConstraint GasConstraints
	zeroGasConstraint.GasAssetCount = gasAssetCount

	// set witness
	zeroAccountConstraint := GasAccountConstraints{
		AccountIndex:    0,
		L1Address:       0,
		AccountPk:       types.EmptyPublicKeyWitness(),
		Nonce:           0,
		CollectionNonce: 0,
		AssetRoot:       0,
		GasAssetCount:   gasAssetCount,
	}
	zeroAccountConstraint.AssetsInfo = make([]types.AccountAssetConstraints, gasAssetCount)
	// set assets witness
	for _, assetId := range gasAssets {
		zeroAccountConstraint.AssetsInfo[assetId] = types.AccountAssetConstraints{
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
		L1Address:       account.L1Address,
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
