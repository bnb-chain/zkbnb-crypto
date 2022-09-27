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
	"log"

	"github.com/consensys/gnark/std/hash/mimc"

	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

type BlockConstraints struct {
	BlockNumber     Variable
	CreatedAt       Variable
	OldStateRoot    Variable `gnark:",public"`
	NewStateRoot    Variable `gnark:",public"`
	BlockCommitment Variable `gnark:",public"`
	Txs             []TxConstraints
	TxsCount        int
	Gas             GasConstraints
	GasAssetIds     []int64
}

func (circuit BlockConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	err = VerifyBlock(api, circuit, hFunc)
	if err != nil {
		return err
	}
	return nil
}

func VerifyBlock(
	api API,
	block BlockConstraints,
	hFunc MiMC,
) (err error) {
	var (
		onChainOpsCount Variable
		isOnChainOp     Variable
		roots           [types.NbRoots]Variable
		count           = 4
		gasAssets       [NbGasAssetsPerTx]Variable
		gasDeltas       [NbGasAssetsPerTx]Variable
	)
	pendingCommitmentData := make([]Variable, types.PubDataSizePerTx*block.TxsCount+5)
	// write basic info into hFunc
	pendingCommitmentData[0] = block.BlockNumber
	pendingCommitmentData[1] = block.CreatedAt
	pendingCommitmentData[2] = block.OldStateRoot
	pendingCommitmentData[3] = block.NewStateRoot
	api.AssertIsEqual(block.OldStateRoot, block.Txs[0].StateRootBefore)

	gasAssetCount := len(block.GasAssetIds)
	blockGasDeltas := make([]Variable, gasAssetCount)
	for i := 0; i < gasAssetCount; i++ {
		blockGasDeltas[i] = 0
	}

	onChainOpsCount = 0
	isOnChainOp, pendingPubData, roots, gasAssets, gasDeltas, err := VerifyTransaction(api, block.Txs[0], hFunc, block.CreatedAt)
	if err != nil {
		log.Println("[VerifyBlock] unable to verify block:", err)
		return err
	}
	for i := 0; i < types.PubDataSizePerTx; i++ {
		pendingCommitmentData[count] = pendingPubData[i]
		count++
	}
	onChainOpsCount = api.Add(onChainOpsCount, isOnChainOp)

	for i := 0; i < gasAssetCount; i++ {
		for j := 0; j < NbGasAssetsPerTx; j++ {
			found := api.IsZero(api.Sub(block.GasAssetIds[i], gasAssets[j]))
			delta := api.Select(found, gasDeltas[j], types.ZeroInt)
			blockGasDeltas[i] = api.Add(blockGasDeltas[i], delta)
		}
	}

	for i := 1; i < block.TxsCount; i++ {
		isEmptyTx := api.IsZero(api.Sub(block.Txs[i].TxType, types.TxTypeEmptyTx))
		notEmptyTx := api.IsZero(isEmptyTx)
		types.IsVariableEqual(api, notEmptyTx, block.Txs[i-1].StateRootAfter, block.Txs[i].StateRootBefore)
		hFunc.Reset()
		isOnChainOp, pendingPubData, roots, gasAssets, gasDeltas, err = VerifyTransaction(api, block.Txs[i], hFunc, block.CreatedAt)
		if err != nil {
			log.Println("[VerifyBlock] unable to verify block:", err)
			return err
		}
		for j := 0; j < types.PubDataSizePerTx; j++ {
			pendingCommitmentData[count] = pendingPubData[j]
			count++
		}
		onChainOpsCount = api.Add(onChainOpsCount, isOnChainOp)
		for i := 0; i < gasAssetCount; i++ {
			for j := 0; j < NbGasAssetsPerTx; j++ {
				found := api.IsZero(api.Sub(block.GasAssetIds[i], gasAssets[j]))
				delta := api.Select(found, gasDeltas[j], types.ZeroInt)
				blockGasDeltas[i] = api.Add(blockGasDeltas[i], delta)
			}
		}
	}

	hFunc.Reset()
	stateRoot, err := VerifyGas(api, block.Gas, blockGasDeltas, hFunc, roots)
	isEmptyTx := api.IsZero(api.Sub(block.Txs[block.TxsCount-1].TxType, types.TxTypeEmptyTx))
	notEmptyTx := api.IsZero(isEmptyTx)
	types.IsVariableEqual(api, notEmptyTx, block.NewStateRoot, stateRoot)

	pendingCommitmentData[count] = onChainOpsCount
	commitments, _ := api.Compiler().NewHint(types.Keccak256, 1, pendingCommitmentData[:]...)
	api.AssertIsEqual(commitments[0], block.BlockCommitment)
	return nil
}

func SetBlockWitness(oBlock *Block) (witness BlockConstraints, err error) {
	witness = BlockConstraints{
		BlockNumber:     oBlock.BlockNumber,
		CreatedAt:       oBlock.CreatedAt,
		OldStateRoot:    oBlock.OldStateRoot,
		NewStateRoot:    oBlock.NewStateRoot,
		BlockCommitment: oBlock.BlockCommitment,
	}
	for i := 0; i < len(oBlock.Txs); i++ {
		tx, err := SetTxWitness(oBlock.Txs[i])
		witness.Txs = append(witness.Txs, tx)
		if err != nil {
			log.Println("fail to set tx witness: ", err.Error())
			return witness, err
		}
	}

	witness.Gas, err = SetGasWitness(oBlock.Gas)
	if err != nil {
		log.Println("fail to set gas witness: ", err.Error())
		return witness, err
	}
	return witness, nil
}

func GetZeroTxConstraint() TxConstraints {
	var zeroTxConstraint TxConstraints
	zeroTxConstraint.TxType = 0
	zeroTxConstraint.RegisterZnsTxInfo = types.EmptyRegisterZnsTxWitness()
	zeroTxConstraint.CreatePairTxInfo = types.EmptyCreatePairTxWitness()
	zeroTxConstraint.UpdatePairRateTxInfo = types.EmptyUpdatePairRateTxWitness()
	zeroTxConstraint.DepositTxInfo = types.EmptyDepositTxWitness()
	zeroTxConstraint.DepositNftTxInfo = types.EmptyDepositNftTxWitness()
	zeroTxConstraint.TransferTxInfo = types.EmptyTransferTxWitness()
	zeroTxConstraint.SwapTxInfo = types.EmptySwapTxWitness()
	zeroTxConstraint.AddLiquidityTxInfo = types.EmptyAddLiquidityTxWitness()
	zeroTxConstraint.RemoveLiquidityTxInfo = types.EmptyRemoveLiquidityTxWitness()
	zeroTxConstraint.CreateCollectionTxInfo = types.EmptyCreateCollectionTxWitness()
	zeroTxConstraint.MintNftTxInfo = types.EmptyMintNftTxWitness()
	zeroTxConstraint.TransferNftTxInfo = types.EmptyTransferNftTxWitness()
	zeroTxConstraint.AtomicMatchTxInfo = types.EmptyAtomicMatchTxWitness()
	zeroTxConstraint.CancelOfferTxInfo = types.EmptyCancelOfferTxWitness()
	zeroTxConstraint.WithdrawTxInfo = types.EmptyWithdrawTxWitness()
	zeroTxConstraint.WithdrawNftTxInfo = types.EmptyWithdrawNftTxWitness()
	zeroTxConstraint.FullExitTxInfo = types.EmptyFullExitTxWitness()
	zeroTxConstraint.FullExitNftTxInfo = types.EmptyFullExitNftTxWitness()
	zeroTxConstraint.Signature = EmptySignatureWitness()
	zeroTxConstraint.Nonce = 0
	zeroTxConstraint.ExpiredAt = 0

	// set common account & merkle parts
	// account root before
	zeroTxConstraint.AccountRootBefore = 0
	zeroTxConstraint.LiquidityRootBefore = 0
	zeroTxConstraint.NftRootBefore = 0
	zeroTxConstraint.StateRootBefore = 0
	zeroTxConstraint.StateRootAfter = 0

	// before
	zeroTxConstraint.LiquidityBefore = LiquidityConstraints{
		PairIndex:            0,
		AssetAId:             0,
		AssetA:               0,
		AssetBId:             0,
		AssetB:               0,
		LpAmount:             0,
		KLast:                0,
		FeeRate:              0,
		TreasuryAccountIndex: 0,
		TreasuryRate:         0,
	}

	zeroTxConstraint.NftBefore = NftConstraints{
		NftIndex:            0,
		NftContentHash:      0,
		CreatorAccountIndex: 0,
		OwnerAccountIndex:   0,
		NftL1Address:        0,
		NftL1TokenId:        0,
		CreatorTreasuryRate: 0,
		CollectionId:        0,
	}
	// account before info, size is 4
	for i := 0; i < NbAccountsPerTx; i++ {
		// set witness
		zeroAccountConstraint := types.AccountConstraints{
			AccountIndex:    0,
			AccountNameHash: 0,
			AccountPk:       types.EmptyPublicKeyWitness(),
			Nonce:           0,
			CollectionNonce: 0,
			AssetRoot:       0,
		}
		// set assets witness
		for i := 0; i < NbAccountAssetsPerAccount; i++ {
			zeroAccountConstraint.AssetsInfo[i] = types.AccountAssetConstraints{
				AssetId:                  0,
				Balance:                  0,
				LpAmount:                 0,
				OfferCanceledOrFinalized: 0,
			}
		}
		// accounts info before
		zeroTxConstraint.AccountsInfoBefore[i] = zeroAccountConstraint
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			for k := 0; k < AssetMerkleLevels; k++ {
				// account assets before
				zeroTxConstraint.MerkleProofsAccountAssetsBefore[i][j][k] = 0
			}
		}
		for j := 0; j < AccountMerkleLevels; j++ {
			// account before
			zeroTxConstraint.MerkleProofsAccountBefore[i][j] = 0
		}
	}
	for i := 0; i < LiquidityMerkleLevels; i++ {
		// liquidity assets before
		zeroTxConstraint.MerkleProofsLiquidityBefore[i] = 0
	}
	for i := 0; i < NftMerkleLevels; i++ {
		// nft assets before
		zeroTxConstraint.MerkleProofsNftBefore[i] = 0
	}
	return zeroTxConstraint
}
