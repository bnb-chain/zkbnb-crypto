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
	"github.com/consensys/gnark/std/hash/poseidon"
	"github.com/consensys/gnark/std/hash/sha256"
	"log"

	"github.com/consensys/gnark/std/hash/mimc"

	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

type BlockConstraints struct {
	BlockNumber     Variable
	CreatedAt       Variable
	OldStateRoot    Variable
	NewStateRoot    Variable
	BlockCommitment Variable `gnark:",public"`
	Txs             []TxConstraints
	TxsCount        int
	Gas             GasConstraints
	GasAssetIds     []int64
	GasAccountIndex int64
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
		gasDeltas       [NbGasAssetsPerTx]GasDeltaConstraints
		needGas         Variable
	)
	blockInfoCount := 5
	pendingCommitmentData := make([]Variable, types.PubDataBitsSizePerTx*block.TxsCount+blockInfoCount)
	// write basic info into hFunc
	pendingCommitmentData[0] = block.BlockNumber
	pendingCommitmentData[1] = block.CreatedAt
	pendingCommitmentData[2] = block.OldStateRoot
	pendingCommitmentData[3] = block.NewStateRoot
	api.AssertIsEqual(block.OldStateRoot, block.Txs[0].StateRootBefore)

	gasAssetCount := len(block.GasAssetIds)
	blockGasDeltas := make([]Variable, gasAssetCount)
	for i := 0; i < gasAssetCount; i++ {
		blockGasDeltas[i] = Variable(0)
	}
	for i := 0; i < types.NbRoots; i++ {
		roots[i] = Variable(0)
	}

	onChainOpsCount = 0
	isOnChainOp, pendingPubData, roots, gasDeltas, err := VerifyTransaction(api, block.Txs[0], hFunc, block.CreatedAt, block.GasAssetIds, roots)
	if err != nil {
		log.Println("unable to verify transaction, err:", err)
		return err
	}
	for i := 0; i < types.PubDataBitsSizePerTx; i++ {
		pendingCommitmentData[count] = pendingPubData[i]
		count++
	}
	onChainOpsCount = api.Add(onChainOpsCount, isOnChainOp)

	matched := Variable(0)
	for i := 0; i < gasAssetCount; i++ {
		for j := 0; j < NbGasAssetsPerTx; j++ {
			found := api.IsZero(api.Sub(block.GasAssetIds[i], gasDeltas[j].AssetId))
			delta := api.Select(found, gasDeltas[j].BalanceDelta, types.ZeroInt)
			blockGasDeltas[i] = api.Add(blockGasDeltas[i], delta)
			matched = api.Or(matched, found)
		}
	}
	api.AssertIsEqual(matched, 1)

	for i := 1; i < block.TxsCount; i++ {
		api.AssertIsEqual(block.Txs[i-1].StateRootAfter, block.Txs[i].StateRootBefore)
		hFunc.Reset()
		isOnChainOp, pendingPubData, roots, gasDeltas, err = VerifyTransaction(api, block.Txs[i], hFunc, block.CreatedAt, block.GasAssetIds, roots)
		if err != nil {
			log.Println("unable to verify transaction, err:", err)
			return err
		}
		for j := 0; j < types.PubDataBitsSizePerTx; j++ {
			pendingCommitmentData[count] = pendingPubData[j]
			count++
		}
		onChainOpsCount = api.Add(onChainOpsCount, isOnChainOp)

		matched = Variable(0)
		for i := 0; i < gasAssetCount; i++ {
			for j := 0; j < NbGasAssetsPerTx; j++ {
				found := api.IsZero(api.Sub(block.GasAssetIds[i], gasDeltas[j].AssetId))
				delta := api.Select(found, gasDeltas[j].BalanceDelta, types.ZeroInt)
				blockGasDeltas[i] = api.Add(blockGasDeltas[i], delta)
				matched = api.Or(matched, found)
			}
		}
		api.AssertIsEqual(matched, 1)
	}

	needGas = Variable(0)
	for i := 0; i < block.TxsCount; i++ {
		changePubKeyTx := api.IsZero(api.Sub(block.Txs[i].TxType, types.TxTypeChangePubKey))
		transferTx := api.IsZero(api.Sub(block.Txs[i].TxType, types.TxTypeTransfer))
		withdrawTx := api.IsZero(api.Sub(block.Txs[i].TxType, types.TxTypeWithdraw))
		createCollectionTx := api.IsZero(api.Sub(block.Txs[i].TxType, types.TxTypeCreateCollection))
		mintNftTx := api.IsZero(api.Sub(block.Txs[i].TxType, types.TxTypeMintNft))
		cancelOfferTx := api.IsZero(api.Sub(block.Txs[i].TxType, types.TxTypeCancelOffer))
		atomicMatchTx := api.IsZero(api.Sub(block.Txs[i].TxType, types.TxTypeAtomicMatch))
		withdrawNftTx := api.IsZero(api.Sub(block.Txs[i].TxType, types.TxTypeWithdrawNft))
		transferNft := api.IsZero(api.Sub(block.Txs[i].TxType, types.TxTypeTransferNft))
		txNeedGas := api.Or(api.Or(api.Or(api.Or(api.Or(api.Or(api.Or(api.Or(transferTx, changePubKeyTx), withdrawTx), createCollectionTx), mintNftTx), cancelOfferTx), atomicMatchTx), withdrawNftTx), transferNft)
		needGas = api.Or(needGas, txNeedGas)
	}

	types.IsVariableEqual(api, needGas, block.Gas.AccountInfoBefore.AccountIndex, block.GasAccountIndex)
	roots[0], err = VerifyGas(api, block.Gas, needGas, blockGasDeltas, roots[0])
	if err != nil {
		log.Println("unable to verify gas, err:", err)
		return err
	}
	newStateRoot := poseidon.Poseidon(api, roots[:]...)
	types.IsVariableEqual(api, needGas, block.NewStateRoot, newStateRoot)

	notNeedGas := api.Xor(1, needGas)
	types.IsVariableEqual(api, notNeedGas, block.NewStateRoot, block.Txs[block.TxsCount-1].StateRootAfter)

	pendingCommitmentData[count] = onChainOpsCount
	outputBytesCount := blockInfoCount*32 + (types.PubDataBitsSizePerTx*block.TxsCount)/8
	pubDataBytes, _ := api.Compiler().NewHint(types.PubDataToBytes, outputBytesCount, pendingCommitmentData[:]...)
	commitment := sha256.Sha256Api(api, pubDataBytes[:]...)
	api.AssertIsEqual(commitment, block.BlockCommitment)
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
	zeroTxConstraint.ChangePubKeyTxInfo = types.EmptyChangePubKeyTxWitness()
	zeroTxConstraint.DepositTxInfo = types.EmptyDepositTxWitness()
	zeroTxConstraint.DepositNftTxInfo = types.EmptyDepositNftTxWitness()
	zeroTxConstraint.TransferTxInfo = types.EmptyTransferTxWitness()
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
	zeroTxConstraint.NftRootBefore = 0
	zeroTxConstraint.StateRootBefore = 0
	zeroTxConstraint.StateRootAfter = 0

	// before
	zeroTxConstraint.NftBefore = NftConstraints{
		NftIndex:            0,
		NftContentHash:      [2]Variable{0, 0},
		CreatorAccountIndex: 0,
		OwnerAccountIndex:   0,
		RoyaltyRate:         0,
		CollectionId:        0,
		NftContentType:      0,
	}
	// account before info, size is 4
	for i := 0; i < NbAccountsPerTx; i++ {
		// set witness
		zeroAccountConstraint := types.AccountConstraints{
			AccountIndex:    0,
			L1Address:       0,
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
	for i := 0; i < NftMerkleLevels; i++ {
		// nft assets before
		zeroTxConstraint.MerkleProofsNftBefore[i] = 0
	}
	return zeroTxConstraint
}
