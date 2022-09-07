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

package block

import (
	"encoding/hex"
	"errors"
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/encode/abi"
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/encode/eip712"
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/std"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"log"
)

type TxConstraints struct {
	// tx type
	TxType Variable
	// different transactions
	RegisterZnsTxInfo      RegisterZnsTxConstraints
	CreatePairTxInfo       CreatePairTxConstraints
	UpdatePairRateTxInfo   UpdatePairRateTxConstraints
	DepositTxInfo          DepositTxConstraints
	DepositNftTxInfo       DepositNftTxConstraints
	TransferTxInfo         TransferTxConstraints
	SwapTxInfo             SwapTxConstraints
	AddLiquidityTxInfo     AddLiquidityTxConstraints
	RemoveLiquidityTxInfo  RemoveLiquidityTxConstraints
	CreateCollectionTxInfo CreateCollectionTxConstraints
	MintNftTxInfo          MintNftTxConstraints
	TransferNftTxInfo      TransferNftTxConstraints
	AtomicMatchTxInfo      AtomicMatchTxConstraints
	CancelOfferTxInfo      CancelOfferTxConstraints
	WithdrawTxInfo         WithdrawTxConstraints
	WithdrawNftTxInfo      WithdrawNftTxConstraints
	FullExitTxInfo         FullExitTxConstraints
	FullExitNftTxInfo      FullExitNftTxConstraints

	ValueConstraints ValuesConstraints // variable name
	// signature
	Signature std.EcdsaSignatureConstraints

	// nonce
	Nonce Variable
	// expired at
	ExpiredAt Variable
	// account root before
	AccountRootBefore Variable
	// account before info, size is 5
	AccountsInfoBefore [NbAccountsPerTx]std.AccountConstraints
	// liquidity root before
	LiquidityRootBefore Variable
	// liquidity before
	LiquidityBefore std.LiquidityConstraints
	// nft root before
	NftRootBefore Variable
	// nft before
	NftBefore std.NftConstraints
	// state root before
	StateRootBefore Variable
	// before account asset merkle proof
	MerkleProofsAccountAssetsBefore [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels]Variable
	// before liquidity merkle proof
	MerkleProofsLiquidityBefore [LiquidityMerkleLevels]Variable
	// before nft tree merkle proof
	MerkleProofsNftBefore [NftMerkleLevels]Variable
	// before account merkle proof
	MerkleProofsAccountBefore [NbAccountsPerTx][AccountMerkleLevels]Variable
	// state root after
	StateRootAfter Variable
}

func (circuit TxConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	_, _, err = VerifyTransaction(api, circuit, hFunc, 1633400952228)
	if err != nil {
		return err
	}
	return nil
}

func VerifyTransaction(
	api API,
	tx TxConstraints,
	hFunc MiMC,
	blockCreatedAt Variable,
) (isOnChainOp Variable, pubData [std.PubDataSizePerTx]Variable, err error) {
	// compute tx type
	isEmptyTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeEmptyTx))
	isRegisterZnsTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeRegisterZns))
	isCreatePairTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeCreatePair))
	isUpdatePairRateTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeUpdatePairRate))
	isDepositTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeDeposit))
	isDepositNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeDepositNft))
	isTransferTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeTransfer))
	isSwapTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeSwap))
	isAddLiquidityTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeAddLiquidity))
	isRemoveLiquidityTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeRemoveLiquidity))
	isWithdrawTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeWithdraw))
	isCreateCollectionTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeCreateCollection))
	isMintNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeMintNft))
	isTransferNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeTransferNft))
	isAtomicMatchTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeAtomicMatch))
	isCancelOfferTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeCancelOffer))
	isWithdrawNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeWithdrawNft))
	isFullExitTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeFullExit))
	isFullExitNftTx := api.IsZero(api.Sub(tx.TxType, std.TxTypeFullExitNft))

	// verify nonce
	isLayer2Tx := api.Add(
		isTransferTx,
		isSwapTx,
		isAddLiquidityTx,
		isRemoveLiquidityTx,
		isWithdrawTx,
		isCreateCollectionTx,
		isMintNftTx,
		isTransferNftTx,
		isAtomicMatchTx,
		isCancelOfferTx,
		isWithdrawNftTx,
	)

	isOnChainOp = api.Add(
		isRegisterZnsTx,
		isDepositTx,
		isDepositNftTx,
		isCreatePairTx,
		isUpdatePairRateTx,
		isWithdrawTx,
		isWithdrawNftTx,
		isFullExitTx,
		isFullExitNftTx,
	)

	// get hash value from tx based on tx type
	// transfer tx
	hashVal := std.ComputeHashFromTransferTx(tx.TransferTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	// swap tx
	hashValCheck := std.ComputeHashFromSwapTx(tx.SwapTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	hashVal = api.Select(isSwapTx, hashValCheck, hashVal)
	// add liquidity tx
	hashValCheck = std.ComputeHashFromAddLiquidityTx(tx.AddLiquidityTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	hashVal = api.Select(isAddLiquidityTx, hashValCheck, hashVal)
	// remove liquidity tx
	hashValCheck = std.ComputeHashFromRemoveLiquidityTx(tx.RemoveLiquidityTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	hashVal = api.Select(isRemoveLiquidityTx, hashValCheck, hashVal)
	// withdraw tx
	hashValCheck = std.ComputeHashFromWithdrawTx(tx.WithdrawTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	hashVal = api.Select(isWithdrawTx, hashValCheck, hashVal)
	// createCollection tx
	hashValCheck = std.ComputeHashFromCreateCollectionTx(tx.CreateCollectionTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	hashVal = api.Select(isCreateCollectionTx, hashValCheck, hashVal)
	// mint nft tx
	hashValCheck = std.ComputeHashFromMintNftTx(api, tx.MintNftTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	hashVal = api.Select(isMintNftTx, hashValCheck, hashVal)
	// transfer nft tx
	hashValCheck = std.ComputeHashFromTransferNftTx(tx.TransferNftTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	hashVal = api.Select(isTransferNftTx, hashValCheck, hashVal)
	// set nft price tx
	hashValCheck = std.ComputeHashFromAtomicMatchTx(tx.AtomicMatchTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	hashVal = api.Select(isAtomicMatchTx, hashValCheck, hashVal)
	// buy nft tx
	hashValCheck = std.ComputeHashFromCancelOfferTx(tx.CancelOfferTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	hashVal = api.Select(isCancelOfferTx, hashValCheck, hashVal)
	// withdraw nft tx
	hashValCheck = std.ComputeHashFromWithdrawNftTx(tx.WithdrawNftTxInfo, tx.Nonce, tx.ExpiredAt, hFunc)
	hashVal = api.Select(isWithdrawNftTx, hashValCheck, hashVal)
	hFunc.Reset()

	std.IsVariableEqual(api, isLayer2Tx, tx.AccountsInfoBefore[0].Nonce, tx.Nonce)
	// verify signature

	encoder, err := abi.NewAbiEncoder(api, tx.TxType)
	if err != nil {
		return nil, pubData, err
	}

	res, err := encoder.Pack(api, tx.TxType, tx.ValueConstraints.Values[:]...)
	if err != nil {
		return nil, pubData, err
	}

	innerKeccakRes, err := api.Compiler().NewHint(eip712.GenerateKeccakHint, 32, res...)

	prefix, err := hex.DecodeString(abi.HexPrefixAndEip712DomainKeccakHash)
	if err != nil {
		return nil, pubData, err
	}
	prefixVariables := make([]frontend.Variable, len(prefix))
	for i := 0; i < len(prefix); i++ {
		prefixVariables[i] = prefix[i]
	}

	outerBytes := append(prefixVariables, innerKeccakRes...)
	keccakRes, err := api.Compiler().NewHint(eip712.GenerateKeccakHint, 32, outerBytes...)

	SIG := make([]frontend.Variable, 0)
	SIG = append(SIG, tx.Signature.R[:]...)
	SIG = append(SIG, tx.Signature.S[:]...)
	SIG = append(SIG, tx.Signature.V)

	ecdsaCircuit := eip712.Secp256k1Circuit{SIG: SIG, MSG: keccakRes, PK: tx.AccountsInfoBefore[0].AccountPk.PkBytes[:]}
	valid, err := ecdsaCircuit.Verify(api)

	std.IsVariableEqual(api, isLayer2Tx, valid, std.OneInt)
	if err != nil {
		log.Println("[VerifyTx] invalid signature:", err)
		return nil, pubData, err
	}

	// verify transactions
	for i := 0; i < std.PubDataSizePerTx; i++ {
		pubData[i] = 0
	}
	pubDataCheck := std.VerifyRegisterZNSTx(api, isRegisterZnsTx, tx.RegisterZnsTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isRegisterZnsTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyCreatePairTx(api, isCreatePairTx, tx.CreatePairTxInfo, tx.LiquidityBefore)
	pubData = SelectPubData(api, isCreatePairTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyUpdatePairRateTx(api, isUpdatePairRateTx, tx.UpdatePairRateTxInfo, tx.LiquidityBefore)
	pubData = SelectPubData(api, isUpdatePairRateTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyDepositTx(api, isDepositTx, tx.DepositTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isDepositTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyDepositNftTx(api, isDepositNftTx, tx.DepositNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	pubData = SelectPubData(api, isDepositNftTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyTransferTx(api, isTransferTx, &tx.TransferTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isTransferTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifySwapTx(api, isSwapTx, &tx.SwapTxInfo, tx.AccountsInfoBefore, tx.LiquidityBefore)
	pubData = SelectPubData(api, isSwapTx, pubDataCheck, pubData)
	pubDataCheck, err = std.VerifyAddLiquidityTx(api, isAddLiquidityTx, &tx.AddLiquidityTxInfo, tx.AccountsInfoBefore, tx.LiquidityBefore)
	if err != nil {
		return nil, pubData, err
	}
	pubData = SelectPubData(api, isAddLiquidityTx, pubDataCheck, pubData)
	pubDataCheck, err = std.VerifyRemoveLiquidityTx(api, isRemoveLiquidityTx, &tx.RemoveLiquidityTxInfo, tx.AccountsInfoBefore, tx.LiquidityBefore)
	if err != nil {
		return nil, pubData, err
	}
	pubData = SelectPubData(api, isRemoveLiquidityTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyCreateCollectionTx(api, isCreateCollectionTx, &tx.CreateCollectionTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isCreateCollectionTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyWithdrawTx(api, isWithdrawTx, &tx.WithdrawTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isWithdrawTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyMintNftTx(api, isMintNftTx, &tx.MintNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	pubData = SelectPubData(api, isMintNftTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyTransferNftTx(api, isTransferNftTx, &tx.TransferNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	pubData = SelectPubData(api, isTransferNftTx, pubDataCheck, pubData)
	hFunc.Reset()
	pubDataCheck, err = std.VerifyAtomicMatchTx(
		api, isAtomicMatchTx, &tx.AtomicMatchTxInfo, tx.AccountsInfoBefore, tx.NftBefore, blockCreatedAt,
		hFunc,
	)
	if err != nil {
		return nil, pubData, err
	}
	pubData = SelectPubData(api, isAtomicMatchTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyCancelOfferTx(api, isCancelOfferTx, &tx.CancelOfferTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isCancelOfferTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyWithdrawNftTx(api, isWithdrawNftTx, &tx.WithdrawNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	pubData = SelectPubData(api, isWithdrawNftTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyFullExitTx(api, isFullExitTx, tx.FullExitTxInfo, tx.AccountsInfoBefore)
	pubData = SelectPubData(api, isFullExitTx, pubDataCheck, pubData)
	pubDataCheck = std.VerifyFullExitNftTx(api, isFullExitNftTx, tx.FullExitNftTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	pubData = SelectPubData(api, isFullExitNftTx, pubDataCheck, pubData)

	// verify timestamp
	std.IsVariableLessOrEqual(api, isLayer2Tx, blockCreatedAt, tx.ExpiredAt)

	// empty delta
	var (
		assetDeltas    [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints
		liquidityDelta LiquidityDeltaConstraints
		nftDelta       NftDeltaConstraints
	)
	for i := 0; i < NbAccountsPerTx; i++ {
		assetDeltas[i] = [NbAccountAssetsPerAccount]AccountAssetDeltaConstraints{
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
			EmptyAccountAssetDeltaConstraints(),
		}
	}
	liquidityDelta = LiquidityDeltaConstraints{
		AssetAId:             tx.LiquidityBefore.AssetAId,
		AssetBId:             tx.LiquidityBefore.AssetBId,
		AssetADelta:          std.ZeroInt,
		AssetBDelta:          std.ZeroInt,
		LpDelta:              std.ZeroInt,
		KLast:                tx.LiquidityBefore.KLast,
		FeeRate:              tx.LiquidityBefore.FeeRate,
		TreasuryAccountIndex: tx.LiquidityBefore.TreasuryAccountIndex,
		TreasuryRate:         tx.LiquidityBefore.TreasuryRate,
	}
	nftDelta = NftDeltaConstraints{
		CreatorAccountIndex: tx.NftBefore.CreatorAccountIndex,
		OwnerAccountIndex:   tx.NftBefore.OwnerAccountIndex,
		NftContentHash:      tx.NftBefore.NftContentHash,
		NftL1Address:        tx.NftBefore.NftL1Address,
		NftL1TokenId:        tx.NftBefore.NftL1TokenId,
		CreatorTreasuryRate: tx.NftBefore.CreatorTreasuryRate,
		CollectionId:        tx.NftBefore.CollectionId,
	}

	// register
	accountDelta := GetAccountDeltaFromRegisterZNS(tx.RegisterZnsTxInfo)
	// deposit
	assetDeltasCheck := GetAssetDeltasFromDeposit(tx.DepositTxInfo)
	assetDeltas = SelectAssetDeltas(api, isDepositTx, assetDeltasCheck, assetDeltas)
	// create pair
	liquidityDeltaCheck := GetLiquidityDeltaFromCreatePair(tx.CreatePairTxInfo)
	liquidityDelta = SelectLiquidityDelta(api, isCreatePairTx, liquidityDeltaCheck, liquidityDelta)
	// update pair rate
	liquidityDeltaCheck = GetLiquidityDeltaFromUpdatePairRate(tx.UpdatePairRateTxInfo, tx.LiquidityBefore)
	liquidityDelta = SelectLiquidityDelta(api, isUpdatePairRateTx, liquidityDeltaCheck, liquidityDelta)
	// generic transfer
	assetDeltasCheck = GetAssetDeltasFromTransfer(api, tx.TransferTxInfo)
	assetDeltas = SelectAssetDeltas(api, isTransferTx, assetDeltasCheck, assetDeltas)
	// swap
	assetDeltasCheck, liquidityDeltaCheck = GetAssetDeltasAndLiquidityDeltaFromSwap(api, tx.SwapTxInfo, tx.LiquidityBefore)
	assetDeltas = SelectAssetDeltas(api, isSwapTx, assetDeltasCheck, assetDeltas)
	liquidityDelta = SelectLiquidityDelta(api, isSwapTx, liquidityDeltaCheck, liquidityDelta)
	// add liquidity
	assetDeltasCheck, liquidityDeltaCheck = GetAssetDeltasAndLiquidityDeltaFromAddLiquidity(api, tx.AddLiquidityTxInfo, tx.LiquidityBefore)
	assetDeltas = SelectAssetDeltas(api, isAddLiquidityTx, assetDeltasCheck, assetDeltas)
	liquidityDelta = SelectLiquidityDelta(api, isAddLiquidityTx, liquidityDeltaCheck, liquidityDelta)
	// remove liquidity
	assetDeltasCheck, liquidityDeltaCheck = GetAssetDeltasAndLiquidityDeltaFromRemoveLiquidity(api, tx.RemoveLiquidityTxInfo, tx.LiquidityBefore)
	assetDeltas = SelectAssetDeltas(api, isRemoveLiquidityTx, assetDeltasCheck, assetDeltas)
	liquidityDelta = SelectLiquidityDelta(api, isRemoveLiquidityTx, liquidityDeltaCheck, liquidityDelta)
	// withdraw
	assetDeltasCheck = GetAssetDeltasFromWithdraw(api, tx.WithdrawTxInfo)
	assetDeltas = SelectAssetDeltas(api, isWithdrawTx, assetDeltasCheck, assetDeltas)
	// deposit nft
	nftDeltaCheck := GetNftDeltaFromDepositNft(tx.DepositNftTxInfo)
	nftDelta = SelectNftDeltas(api, isDepositNftTx, nftDeltaCheck, nftDelta)
	// create collection
	assetDeltasCheck = GetAssetDeltasFromCreateCollection(api, tx.CreateCollectionTxInfo)
	assetDeltas = SelectAssetDeltas(api, isCreateCollectionTx, assetDeltasCheck, assetDeltas)
	// mint nft
	assetDeltasCheck, nftDeltaCheck = GetAssetDeltasAndNftDeltaFromMintNft(api, tx.MintNftTxInfo)
	assetDeltas = SelectAssetDeltas(api, isMintNftTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isMintNftTx, nftDeltaCheck, nftDelta)
	// transfer nft
	assetDeltasCheck, nftDeltaCheck = GetAssetDeltasAndNftDeltaFromTransferNft(api, tx.TransferNftTxInfo, tx.NftBefore)
	assetDeltas = SelectAssetDeltas(api, isTransferNftTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isTransferNftTx, nftDeltaCheck, nftDelta)
	// set nft price
	assetDeltasCheck, nftDeltaCheck = GetAssetDeltasAndNftDeltaFromAtomicMatch(api, isAtomicMatchTx, tx.AtomicMatchTxInfo, tx.AccountsInfoBefore, tx.NftBefore)
	assetDeltas = SelectAssetDeltas(api, isAtomicMatchTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isAtomicMatchTx, nftDeltaCheck, nftDelta)
	// buy nft
	assetDeltasCheck = GetAssetDeltasFromCancelOffer(api, isCancelOfferTx, tx.CancelOfferTxInfo, tx.AccountsInfoBefore)
	assetDeltas = SelectAssetDeltas(api, isCancelOfferTx, assetDeltasCheck, assetDeltas)
	// withdraw nft
	assetDeltasCheck, nftDeltaCheck = GetAssetDeltasAndNftDeltaFromWithdrawNft(api, tx.WithdrawNftTxInfo)
	assetDeltas = SelectAssetDeltas(api, isWithdrawNftTx, assetDeltasCheck, assetDeltas)
	nftDelta = SelectNftDeltas(api, isWithdrawNftTx, nftDeltaCheck, nftDelta)
	// full exit
	assetDeltasCheck = GetAssetDeltasFromFullExit(api, tx.FullExitTxInfo)
	assetDeltas = SelectAssetDeltas(api, isFullExitTx, assetDeltasCheck, assetDeltas)
	// full exit nft
	nftDeltaCheck = GetNftDeltaFromFullExitNft()
	nftDelta = SelectNftDeltas(api, isFullExitNftTx, nftDeltaCheck, nftDelta)
	// update accounts
	AccountsInfoAfter := UpdateAccounts(api, tx.AccountsInfoBefore, assetDeltas)
	AccountsInfoAfter[0].AccountNameHash = api.Select(isRegisterZnsTx, accountDelta.AccountNameHash, AccountsInfoAfter[0].AccountNameHash)
	AccountsInfoAfter[0].AccountPk.PkBytes = std.SelectPkBytes(api, isRegisterZnsTx, accountDelta.PubKey.PkBytes, AccountsInfoAfter[0].AccountPk.PkBytes)
	// update nonce
	AccountsInfoAfter[0].Nonce = api.Add(AccountsInfoAfter[0].Nonce, isLayer2Tx)
	AccountsInfoAfter[0].CollectionNonce = api.Add(AccountsInfoAfter[0].CollectionNonce, isCreateCollectionTx)
	// update liquidity
	LiquidityAfter := UpdateLiquidity(api, tx.LiquidityBefore, liquidityDelta)
	// update nft
	NftAfter := UpdateNft(tx.NftBefore, nftDelta)

	// check old state root
	hFunc.Reset()
	hFunc.Write(
		tx.AccountRootBefore,
		tx.LiquidityRootBefore,
		tx.NftRootBefore,
	)
	oldStateRoot := hFunc.Sum()
	notEmptyTx := api.IsZero(isEmptyTx)
	std.IsVariableEqual(api, notEmptyTx, oldStateRoot, tx.StateRootBefore)

	NewAccountRoot := tx.AccountRootBefore
	for i := 0; i < NbAccountsPerTx; i++ {
		var (
			NewAccountAssetsRoot = tx.AccountsInfoBefore[i].AssetRoot
		)
		// verify account asset node hash
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			api.AssertIsLessOrEqual(tx.AccountsInfoBefore[i].AssetsInfo[j].AssetId, LastAccountAssetId)
			assetMerkleHelper := AssetIdToMerkleHelper(api, tx.AccountsInfoBefore[i].AssetsInfo[j].AssetId)
			hFunc.Reset()
			hFunc.Write(
				tx.AccountsInfoBefore[i].AssetsInfo[j].Balance,
				tx.AccountsInfoBefore[i].AssetsInfo[j].LpAmount,
				tx.AccountsInfoBefore[i].AssetsInfo[j].OfferCanceledOrFinalized,
			)
			assetNodeHash := hFunc.Sum()
			// verify account asset merkle proof
			hFunc.Reset()
			std.VerifyMerkleProof(
				api,
				notEmptyTx,
				hFunc,
				NewAccountAssetsRoot,
				assetNodeHash,
				tx.MerkleProofsAccountAssetsBefore[i][j][:],
				assetMerkleHelper,
			)
			hFunc.Reset()
			hFunc.Write(
				AccountsInfoAfter[i].AssetsInfo[j].Balance,
				AccountsInfoAfter[i].AssetsInfo[j].LpAmount,
				AccountsInfoAfter[i].AssetsInfo[j].OfferCanceledOrFinalized,
			)
			assetNodeHash = hFunc.Sum()
			hFunc.Reset()
			// update merkle proof
			NewAccountAssetsRoot = std.UpdateMerkleProof(
				api, hFunc, assetNodeHash, tx.MerkleProofsAccountAssetsBefore[i][j][:], assetMerkleHelper)
		}
		// verify account node hash
		api.AssertIsLessOrEqual(tx.AccountsInfoBefore[i].AccountIndex, LastAccountIndex)
		accountIndexMerkleHelper := AccountIndexToMerkleHelper(api, tx.AccountsInfoBefore[i].AccountIndex)
		hFunc.Reset()
		hFunc.Write(
			tx.AccountsInfoBefore[i].AccountNameHash,
		)
		for pki := range tx.AccountsInfoBefore[i].AccountPk.PkBytes {
			hFunc.Write(tx.AccountsInfoBefore[i].AccountPk.PkBytes[pki])
		}
		hFunc.Write(
			tx.AccountsInfoBefore[i].Nonce,
			tx.AccountsInfoBefore[i].CollectionNonce,
			tx.AccountsInfoBefore[i].AssetRoot,
		)
		accountNodeHash := hFunc.Sum()
		// verify account merkle proof
		hFunc.Reset()
		std.VerifyMerkleProof(
			api,
			notEmptyTx,
			hFunc,
			NewAccountRoot,
			accountNodeHash,
			tx.MerkleProofsAccountBefore[i][:],
			accountIndexMerkleHelper,
		)
		hFunc.Reset()
		hFunc.Write(
			tx.AccountsInfoBefore[i].AccountNameHash,
		)
		for pki := range tx.AccountsInfoBefore[i].AccountPk.PkBytes {
			hFunc.Write(tx.AccountsInfoBefore[i].AccountPk.PkBytes[pki])
		}
		hFunc.Write(
			tx.AccountsInfoBefore[i].Nonce,
			tx.AccountsInfoBefore[i].CollectionNonce,
			NewAccountAssetsRoot,
		)
		accountNodeHash = hFunc.Sum()
		hFunc.Reset()
		// update merkle proof
		NewAccountRoot = std.UpdateMerkleProof(api, hFunc, accountNodeHash, tx.MerkleProofsAccountBefore[i][:], accountIndexMerkleHelper)
	}

	//// liquidity tree
	NewLiquidityRoot := tx.LiquidityRootBefore
	pairIndexMerkleHelper := PairIndexToMerkleHelper(api, tx.LiquidityBefore.PairIndex)
	hFunc.Write(
		tx.LiquidityBefore.AssetAId,
		tx.LiquidityBefore.AssetA,
		tx.LiquidityBefore.AssetBId,
		tx.LiquidityBefore.AssetB,
		tx.LiquidityBefore.LpAmount,
		tx.LiquidityBefore.KLast,
		tx.LiquidityBefore.FeeRate,
		tx.LiquidityBefore.TreasuryAccountIndex,
		tx.LiquidityBefore.TreasuryRate,
	)
	liquidityNodeHash := hFunc.Sum()
	// verify account merkle proof
	hFunc.Reset()
	std.VerifyMerkleProof(
		api,
		notEmptyTx,
		hFunc,
		NewLiquidityRoot,
		liquidityNodeHash,
		tx.MerkleProofsLiquidityBefore[:],
		pairIndexMerkleHelper,
	)
	hFunc.Reset()
	hFunc.Write(
		LiquidityAfter.AssetAId,
		LiquidityAfter.AssetA,
		LiquidityAfter.AssetBId,
		LiquidityAfter.AssetB,
		LiquidityAfter.LpAmount,
		LiquidityAfter.KLast,
		LiquidityAfter.FeeRate,
		LiquidityAfter.TreasuryAccountIndex,
		LiquidityAfter.TreasuryRate,
	)
	liquidityNodeHash = hFunc.Sum()
	hFunc.Reset()
	// update merkle proof
	NewLiquidityRoot = std.UpdateMerkleProof(api, hFunc, liquidityNodeHash, tx.MerkleProofsLiquidityBefore[:], pairIndexMerkleHelper)

	//// nft tree
	NewNftRoot := tx.NftRootBefore
	nftIndexMerkleHelper := NftIndexToMerkleHelper(api, tx.NftBefore.NftIndex)
	hFunc.Reset()
	hFunc.Write(
		tx.NftBefore.CreatorAccountIndex,
		tx.NftBefore.OwnerAccountIndex,
		tx.NftBefore.NftContentHash,
		tx.NftBefore.NftL1Address,
		tx.NftBefore.NftL1TokenId,
		tx.NftBefore.CreatorTreasuryRate,
		tx.NftBefore.CollectionId,
	)
	nftNodeHash := hFunc.Sum()
	// verify account merkle proof
	hFunc.Reset()
	std.VerifyMerkleProof(
		api,
		notEmptyTx,
		hFunc,
		NewNftRoot,
		nftNodeHash,
		tx.MerkleProofsNftBefore[:],
		nftIndexMerkleHelper,
	)
	hFunc.Reset()
	hFunc.Write(
		NftAfter.CreatorAccountIndex,
		NftAfter.OwnerAccountIndex,
		NftAfter.NftContentHash,
		NftAfter.NftL1Address,
		NftAfter.NftL1TokenId,
		NftAfter.CreatorTreasuryRate,
		NftAfter.CollectionId,
	)
	nftNodeHash = hFunc.Sum()
	hFunc.Reset()
	// update merkle proof
	NewNftRoot = std.UpdateMerkleProof(api, hFunc, nftNodeHash, tx.MerkleProofsNftBefore[:], nftIndexMerkleHelper)

	// check state root
	hFunc.Reset()
	hFunc.Write(
		NewAccountRoot,
		NewLiquidityRoot,
		NewNftRoot,
	)
	newStateRoot := hFunc.Sum()
	std.IsVariableEqual(api, notEmptyTx, newStateRoot, tx.StateRootAfter)
	return isOnChainOp, pubData, nil
}

func EmptyTx() (oTx *Tx) {
	oTx = &Tx{
		TxType:            std.TxTypeEmptyTx,
		Nonce:             0,
		ExpiredAt:         0,
		Signature:         make([]byte, 65),
		AccountRootBefore: make([]byte, 32),
		AccountsInfoBefore: [5]*std.Account{
			std.EmptyAccount(0, make([]byte, 32)),
			std.EmptyAccount(0, make([]byte, 32)),
			std.EmptyAccount(0, make([]byte, 32)),
			std.EmptyAccount(0, make([]byte, 32)),
			std.EmptyAccount(0, make([]byte, 32)),
		},
		LiquidityRootBefore:             make([]byte, 32),
		LiquidityBefore:                 std.EmptyLiquidity(0),
		NftRootBefore:                   make([]byte, 32),
		NftBefore:                       std.EmptyNft(0),
		StateRootBefore:                 make([]byte, 32),
		MerkleProofsAccountAssetsBefore: [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels][]byte{},
		MerkleProofsAccountBefore:       [NbAccountsPerTx][AccountMerkleLevels][]byte{},
		MerkleProofsLiquidityBefore:     [LiquidityMerkleLevels][]byte{},
		MerkleProofsNftBefore:           [NftMerkleLevels][]byte{},
		StateRootAfter:                  make([]byte, 32),
	}
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			for k := 0; k < AssetMerkleLevels; k++ {
				oTx.MerkleProofsAccountAssetsBefore[i][j][k] = make([]byte, 32)
			}
		}
		for j := 0; j < AccountMerkleLevels; j++ {
			oTx.MerkleProofsAccountBefore[i][j] = make([]byte, 32)
		}
	}
	for i := 0; i < LiquidityMerkleLevels; i++ {
		oTx.MerkleProofsLiquidityBefore[i] = make([]byte, 32)
	}
	for i := 0; i < NftMerkleLevels; i++ {
		oTx.MerkleProofsNftBefore[i] = make([]byte, 32)
	}
	return oTx
}

func SetTxWitness(oTx *Tx) (witness TxConstraints, err error) {
	witness.TxType = int64(oTx.TxType)
	witness.RegisterZnsTxInfo = std.EmptyRegisterZnsTxWitness()
	witness.CreatePairTxInfo = std.EmptyCreatePairTxWitness()
	witness.UpdatePairRateTxInfo = std.EmptyUpdatePairRateTxWitness()
	witness.DepositTxInfo = std.EmptyDepositTxWitness()
	witness.DepositNftTxInfo = std.EmptyDepositNftTxWitness()
	witness.TransferTxInfo = std.EmptyTransferTxWitness()
	witness.SwapTxInfo = std.EmptySwapTxWitness()
	witness.AddLiquidityTxInfo = std.EmptyAddLiquidityTxWitness()
	witness.RemoveLiquidityTxInfo = std.EmptyRemoveLiquidityTxWitness()
	witness.CreateCollectionTxInfo = std.EmptyCreateCollectionTxWitness()
	witness.MintNftTxInfo = std.EmptyMintNftTxWitness()
	witness.TransferNftTxInfo = std.EmptyTransferNftTxWitness()
	witness.AtomicMatchTxInfo = std.EmptyAtomicMatchTxWitness()
	witness.CancelOfferTxInfo = std.EmptyCancelOfferTxWitness()
	witness.WithdrawTxInfo = std.EmptyWithdrawTxWitness()
	witness.WithdrawNftTxInfo = std.EmptyWithdrawNftTxWitness()
	witness.FullExitTxInfo = std.EmptyFullExitTxWitness()
	witness.FullExitNftTxInfo = std.EmptyFullExitNftTxWitness()
	witness.Signature = std.EmptyEcdsaSignatureConstraints()
	witness.Nonce = oTx.Nonce
	witness.ExpiredAt = oTx.ExpiredAt
	switch oTx.TxType {
	case std.TxTypeEmptyTx:
		break
	case std.TxTypeRegisterZns:
		witness.RegisterZnsTxInfo = std.SetRegisterZnsTxWitness(oTx.RegisterZnsTxInfo)
		break
	case std.TxTypeCreatePair:
		witness.CreatePairTxInfo = std.SetCreatePairTxWitness(oTx.CreatePairTxInfo)
		break
	case std.TxTypeUpdatePairRate:
		witness.UpdatePairRateTxInfo = std.SetUpdatePairRateTxWitness(oTx.UpdatePairRateTxInfo)
		break
	case std.TxTypeDeposit:
		witness.DepositTxInfo = std.SetDepositTxWitness(oTx.DepositTxInfo)
		break
	case std.TxTypeDepositNft:
		witness.DepositNftTxInfo = std.SetDepositNftTxWitness(oTx.DepositNftTxInfo)
		break
	case std.TxTypeTransfer:
		witness.TransferTxInfo = std.SetTransferTxWitness(oTx.TransferTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])
		witness.ValueConstraints = std.SetTransferTxValuesWitness(oTx.TransferTxInfo, oTx.ExpiredAt, oTx.Nonce)
		break
	case std.TxTypeSwap:
		witness.SwapTxInfo = std.SetSwapTxWitness(oTx.SwapTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])
		witness.ValueConstraints = std.SetSwapTxValuesWitness(oTx.SwapTxInfo, oTx.ExpiredAt, oTx.Nonce)
		break
	case std.TxTypeAddLiquidity:
		witness.AddLiquidityTxInfo = std.SetAddLiquidityTxWitness(oTx.AddLiquidityTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])

		break
	case std.TxTypeRemoveLiquidity:
		witness.RemoveLiquidityTxInfo = std.SetRemoveLiquidityTxWitness(oTx.RemoveLiquidityTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])

		break
	case std.TxTypeWithdraw:
		witness.WithdrawTxInfo = std.SetWithdrawTxWitness(oTx.WithdrawTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])

		break
	case std.TxTypeCreateCollection:
		witness.CreateCollectionTxInfo = std.SetCreateCollectionTxWitness(oTx.CreateCollectionTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])

		break
	case std.TxTypeMintNft:
		witness.MintNftTxInfo = std.SetMintNftTxWitness(oTx.MintNftTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])

		break
	case std.TxTypeTransferNft:
		witness.TransferNftTxInfo = std.SetTransferNftTxWitness(oTx.TransferNftTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])

		break
	case std.TxTypeAtomicMatch:
		witness.AtomicMatchTxInfo = std.SetAtomicMatchTxWitness(oTx.AtomicMatchTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])

		break
	case std.TxTypeCancelOffer:
		witness.CancelOfferTxInfo = std.SetCancelOfferTxWitness(oTx.CancelOfferTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])

		break
	case std.TxTypeWithdrawNft:
		witness.WithdrawNftTxInfo = std.SetWithdrawNftTxWitness(oTx.WithdrawNftTxInfo)
		witness.Signature = std.SetSignatureWitness(oTx.Signature[:32], oTx.Signature[32:64], oTx.Signature[64])

		break
	case std.TxTypeFullExit:
		witness.FullExitTxInfo = std.SetFullExitTxWitness(oTx.FullExitTxInfo)
		break
	case std.TxTypeFullExitNft:
		witness.FullExitNftTxInfo = std.SetFullExitNftTxWitness(oTx.FullExitNftTxInfo)
		break
	default:
		log.Println("[SetTxWitness] invalid oTx type")
		return witness, errors.New("[SetTxWitness] invalid oTx type")
	}
	// set common account & merkle parts
	// account root before
	witness.AccountRootBefore = oTx.AccountRootBefore
	witness.LiquidityRootBefore = oTx.LiquidityRootBefore
	witness.NftRootBefore = oTx.NftRootBefore
	witness.StateRootBefore = oTx.StateRootBefore
	witness.StateRootAfter = oTx.StateRootAfter

	// before
	witness.LiquidityBefore, err = std.SetLiquidityWitness(oTx.LiquidityBefore)
	if err != nil {
		log.Println("[SetTxWitness] unable to set liquidity witness:", err.Error())
		return witness, err
	}
	witness.NftBefore, err = std.SetNftWitness(oTx.NftBefore)
	if err != nil {
		log.Println("[SetTxWitness] unable to set nft witness:", err.Error())
		return witness, err
	}

	// account before info, size is 4
	for i := 0; i < NbAccountsPerTx; i++ {
		// accounts info before
		witness.AccountsInfoBefore[i], err = std.SetAccountWitness(oTx.AccountsInfoBefore[i])
		if err != nil {
			log.Println("[SetTxWitness] err info:", err)
			return witness, err
		}
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			for k := 0; k < AssetMerkleLevels; k++ {
				// account assets before
				witness.MerkleProofsAccountAssetsBefore[i][j][k] = oTx.MerkleProofsAccountAssetsBefore[i][j][k]
			}
		}
		for j := 0; j < AccountMerkleLevels; j++ {
			// account before
			witness.MerkleProofsAccountBefore[i][j] = oTx.MerkleProofsAccountBefore[i][j]
		}
	}
	for i := 0; i < LiquidityMerkleLevels; i++ {
		// liquidity assets before
		witness.MerkleProofsLiquidityBefore[i] = oTx.MerkleProofsLiquidityBefore[i]
	}
	for i := 0; i < NftMerkleLevels; i++ {
		// nft assets before
		witness.MerkleProofsNftBefore[i] = oTx.MerkleProofsNftBefore[i]
	}
	return witness, nil
}
