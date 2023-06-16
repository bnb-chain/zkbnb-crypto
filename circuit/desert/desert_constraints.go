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

package desert

import (
	"github.com/consensys/gnark/std/gkr/gkr"
	"github.com/consensys/gnark/std/hash/sha256"
	"log"

	"github.com/consensys/gnark/std/hash/mimc"

	"github.com/bnb-chain/zkbnb-crypto/circuit"
	desertTypes "github.com/bnb-chain/zkbnb-crypto/circuit/desert/types"
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

type DesertConstraints struct {
	StateRoot  types.Variable
	Commitment types.Variable `gnark:",public"`
	Tx         TxConstraints
	GKRs       gkr.GkrCircuit
}

func (circuit DesertConstraints) Define(api types.API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	err = VerifyDesert(api, circuit, hFunc)
	if err != nil {
		return err
	}
	circuit.GKRs.AssertValid(api, circuit.Commitment)
	return nil
}

func VerifyDesert(
	api types.API,
	constraints DesertConstraints,
	hFunc types.MiMC,
) (err error) {
	count := 1
	blockInfoCount := 1
	pendingCommitmentData := make([]types.Variable, types.PubDataBitsSizePerTx+blockInfoCount)
	// write basic info into hFunc
	pendingCommitmentData[0] = constraints.StateRoot

	// check state root
	newStateRoot := types.MimcWithGkr(api, constraints.Tx.AccountRoot, constraints.Tx.NftRoot)
	api.AssertIsEqual(constraints.StateRoot, newStateRoot)

	pendingPubData, err := VerifyTransaction(api, constraints.Tx)
	if err != nil {
		log.Println("unable to verify transaction, err:", err)
		return err
	}
	for i := 0; i < types.PubDataBitsSizePerTx; i++ {
		pendingCommitmentData[count] = pendingPubData[i]
		count++
	}
	outputBytesCount := blockInfoCount*32 + (types.PubDataBitsSizePerTx)/8
	pubDataBytes, _ := api.Compiler().NewHint(types.PubDataToBytesForDesert, outputBytesCount, pendingCommitmentData[:]...)

	commitment := sha256.Sha256Api(api, pubDataBytes[:]...)
	api.AssertIsEqual(commitment, constraints.Commitment)
	return nil
}

func SetDesertWitness(oBlock *Desert, bN int) (witness DesertConstraints, err error) {
	witness = DesertConstraints{
		StateRoot:  oBlock.StateRoot,
		Commitment: oBlock.Commitment,
	}
	tx, err := SetTxWitness(oBlock.Tx)
	witness.Tx = tx
	if err != nil {
		log.Println("fail to set tx witness: ", err.Error())
		return witness, err
	}
	witness.GKRs.AllocateGKRCircuit(bN)
	return witness, nil
}

func GetZeroTxConstraint() TxConstraints {
	var zeroTxConstraint TxConstraints
	zeroTxConstraint.TxType = 0
	zeroTxConstraint.ExitTxInfo = desertTypes.EmptyExitTxWitness()
	zeroTxConstraint.ExitNftTxInfo = desertTypes.EmptyExitNftTxWitness()

	// set common account & merkle parts
	// account root
	zeroTxConstraint.AccountRoot = 0
	zeroTxConstraint.NftRoot = 0

	//
	zeroTxConstraint.Nft = circuit.NftConstraints{
		NftIndex:            0,
		NftContentHash:      [2]circuit.Variable{0, 0},
		CreatorAccountIndex: 0,
		OwnerAccountIndex:   0,
		RoyaltyRate:         0,
		CollectionId:        0,
		NftContentType:      0,
	}
	// account before info, size is 2
	for i := 0; i < NbAccountsPerTx; i++ {
		// set witness
		zeroAccountConstraint := desertTypes.AccountConstraints{
			AccountIndex:    0,
			L1Address:       0,
			AccountPk:       types.EmptyPublicKeyWitness(),
			Nonce:           0,
			CollectionNonce: 0,
			AssetRoot:       0,
		}
		zeroAccountConstraint.AssetsInfo = types.AccountAssetConstraints{
			AssetId:                  0,
			Balance:                  0,
			OfferCanceledOrFinalized: 0,
		}
		// accounts info before
		zeroTxConstraint.AccountsInfo[i] = zeroAccountConstraint
		for k := 0; k < circuit.AssetMerkleLevels; k++ {
			// account assets before
			zeroTxConstraint.MerkleProofsAccountAssets[i][k] = 0
		}
		for j := 0; j < circuit.AccountMerkleLevels; j++ {
			// account before
			zeroTxConstraint.MerkleProofsAccounts[i][j] = 0
		}
	}
	for i := 0; i < circuit.NftMerkleLevels; i++ {
		// nft assets before
		zeroTxConstraint.MerkleProofsNft[i] = 0
	}
	return zeroTxConstraint
}

func VerifyTransaction(
	api types.API,
	tx TxConstraints,
) (pubData [types.PubDataBitsSizePerTx]types.Variable, err error) {
	// compute tx type
	isEmptyTx := api.IsZero(api.Sub(tx.TxType, desertTypes.TxTypeEmptyTx))
	isExitTx := api.IsZero(api.Sub(tx.TxType, desertTypes.TxTypeExit))
	isExitNftTx := api.IsZero(api.Sub(tx.TxType, desertTypes.TxTypeExitNft))
	isSupportedTx := api.Add(isEmptyTx, isExitTx, isExitNftTx)
	api.AssertIsEqual(isSupportedTx, 1)

	// verify transactions
	for i := 0; i < types.PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}

	pubDataCheck := desertTypes.VerifyExitTx(api, isExitTx, tx.ExitTxInfo, tx.AccountsInfo)
	pubData = circuit.SelectPubData(api, isExitTx, pubDataCheck, pubData)
	desertTypes.VerifyDeltaExitTx(api, isExitTx, tx.ExitTxInfo)

	pubDataCheck = desertTypes.VerifyExitNftTx(api, isExitNftTx, tx.ExitNftTxInfo, tx.AccountsInfo, tx.Nft)
	pubData = circuit.SelectPubData(api, isExitNftTx, pubDataCheck, pubData)
	desertTypes.VerifyDeltaExitNftTx(api, isExitNftTx, tx.ExitNftTxInfo)

	notEmptyTx := api.IsZero(isEmptyTx)

	for i := 0; i < NbAccountsPerTx; i++ {
		// verify account asset node hash
		api.AssertIsLessOrEqual(tx.AccountsInfo[i].AssetsInfo.AssetId, circuit.LastAccountAssetId)
		assetMerkleHelper := circuit.AssetIdToMerkleHelper(api, tx.AccountsInfo[i].AssetsInfo.AssetId)
		assetNodeHash := types.MimcWithGkr(api,
			tx.AccountsInfo[i].AssetsInfo.Balance,
			tx.AccountsInfo[i].AssetsInfo.OfferCanceledOrFinalized)

		// verify account asset merkle proof
		types.VerifyMerkleProof(
			api,
			notEmptyTx,
			tx.AccountsInfo[i].AssetRoot,
			assetNodeHash,
			tx.MerkleProofsAccountAssets[i][:],
			assetMerkleHelper,
		)

		// verify account node hash
		api.AssertIsLessOrEqual(tx.AccountsInfo[i].AccountIndex, circuit.LastAccountIndex)
		accountIndexMerkleHelper := circuit.AccountIndexToMerkleHelper(api, tx.AccountsInfo[i].AccountIndex)
		accountNodeHash := types.MimcWithGkr(api,
			tx.AccountsInfo[i].L1Address,
			tx.AccountsInfo[i].AccountPk.A.X,
			tx.AccountsInfo[i].AccountPk.A.Y,
			tx.AccountsInfo[i].Nonce,
			tx.AccountsInfo[i].CollectionNonce,
			tx.AccountsInfo[i].AssetRoot)
		// verify account merkle proof
		types.VerifyMerkleProof(
			api,
			notEmptyTx,
			tx.AccountRoot,
			accountNodeHash,
			tx.MerkleProofsAccounts[i][:],
			accountIndexMerkleHelper,
		)
	}

	//// nft tree
	api.AssertIsLessOrEqual(tx.Nft.NftIndex, circuit.LastNftIndex)
	nftIndexMerkleHelper := circuit.NftIndexToMerkleHelper(api, tx.Nft.NftIndex)

	nftNodeHash := types.MimcWithGkr(api,
		tx.Nft.CreatorAccountIndex,
		tx.Nft.OwnerAccountIndex,
		tx.Nft.NftContentHash[0],
		tx.Nft.NftContentHash[1],
		tx.Nft.RoyaltyRate,
		tx.Nft.CollectionId,
	)
	// verify account merkle proof
	types.VerifyMerkleProof(
		api,
		notEmptyTx,
		tx.NftRoot,
		nftNodeHash,
		tx.MerkleProofsNft[:],
		nftIndexMerkleHelper,
	)
	return pubData, nil
}
