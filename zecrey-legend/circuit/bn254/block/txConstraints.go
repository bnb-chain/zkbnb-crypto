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
	"errors"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"
	"log"
)

type TxConstraints struct {
	// tx type
	TxType Variable
	// different transactions
	RegisterZnsTxInfo     RegisterZnsTxConstraints
	DepositTxInfo         DepositTxConstraints
	DepositNftTxInfo      DepositNftTxConstraints
	GenericTransferTxInfo GenericTransferTxConstraints
	SwapTxInfo            SwapTxConstraints
	AddLiquidityTxInfo    AddLiquidityTxConstraints
	RemoveLiquidityTxInfo RemoveLiquidityTxConstraints
	MintNftTxInfo         MintNftTxConstraints
	SetNftPriceTxInfo     SetNftPriceTxConstraints
	BuyNftTxInfo          BuyNftTxConstraints
	WithdrawTxInfo        WithdrawTxConstraints
	WithdrawNftTxInfo     WithdrawNftTxConstraints
	// signature
	Signature SignatureConstraints
	// account root before
	AccountRootBefore Variable
	// account before info, size is 4
	AccountsInfoBefore [NbAccountsPerTx]std.AccountConstraints
	// before account asset merkle proof
	MerkleProofsAccountAssetsBefore       [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels]Variable
	MerkleProofsHelperAccountAssetsBefore [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleHelperLevels]Variable
	// before account liquidity merkle proof
	MerkleProofsAccountLiquidityBefore       [NbAccountsPerTx][LiquidityMerkleLevels]Variable
	MerkleProofsHelperAccountLiquidityBefore [NbAccountsPerTx][LiquidityMerkleHelperLevels]Variable
	// before account nft tree merkle proof
	MerkleProofsAccountNftBefore       [NbAccountsPerTx][NftMerkleLevels]Variable
	MerkleProofsHelperAccountNftBefore [NbAccountsPerTx][NftMerkleHelperLevels]Variable
	// before account merkle proof
	MerkleProofsAccountBefore       [NbAccountsPerTx][AccountMerkleLevels]Variable
	MerkleProofsHelperAccountBefore [NbAccountsPerTx][AccountMerkleHelperLevels]Variable
	// account root after
	AccountRootAfter Variable
	// account after info, size is 4
	AccountsInfoAfter [NbAccountsPerTx]std.AccountConstraints
	// after account asset merkle proof
	MerkleProofsAccountAssetsAfter       [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels]Variable
	MerkleProofsHelperAccountAssetsAfter [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleHelperLevels]Variable
	// after account liquidity merkle proof
	MerkleProofsAccountLiquidityAfter       [NbAccountsPerTx][LiquidityMerkleLevels]Variable
	MerkleProofsHelperAccountLiquidityAfter [NbAccountsPerTx][LiquidityMerkleHelperLevels]Variable
	// after account nft tree merkle proof
	MerkleProofsAccountNftAfter       [NbAccountsPerTx][NftMerkleLevels]Variable
	MerkleProofsHelperAccountNftAfter [NbAccountsPerTx][NftMerkleHelperLevels]Variable
	// after account merkle proof
	MerkleProofsAccountAfter       [NbAccountsPerTx][AccountMerkleLevels]Variable
	MerkleProofsHelperAccountAfter [NbAccountsPerTx][AccountMerkleHelperLevels]Variable
}

func (circuit TxConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	err = VerifyTransaction(api, circuit, hFunc, NilHash)
	if err != nil {
		return err
	}
	return nil
}

func VerifyTransaction(
	api API,
	tx TxConstraints,
	hFunc MiMC,
	nilHash Variable,
) error {
	// compute tx type
	isEmptyTx := api.IsZero(api.Sub(tx.TxType, TxTypeEmptyTx))
	isRegisterZnsTx := api.IsZero(api.Sub(tx.TxType, TxTypeRegisterZns))
	isDepositTx := api.IsZero(api.Sub(tx.TxType, TxTypeDeposit))
	isDepositNftTx := api.IsZero(api.Sub(tx.TxType, TxTypeDepositNft))
	isGenericTransferTx := api.IsZero(api.Sub(tx.TxType, TxTypeGenericTransfer))
	isSwapTx := api.IsZero(api.Sub(tx.TxType, TxTypeSwap))
	isAddLiquidityTx := api.IsZero(api.Sub(tx.TxType, TxTypeAddLiquidity))
	isRemoveLiquidityTx := api.IsZero(api.Sub(tx.TxType, TxTypeRemoveLiquidity))
	isWithdrawTx := api.IsZero(api.Sub(tx.TxType, TxTypeWithdraw))
	isMintNftTx := api.IsZero(api.Sub(tx.TxType, TxTypeMintNft))
	isSetNftPriceTx := api.IsZero(api.Sub(tx.TxType, TxTypeSetNftPrice))
	isBuyNftTx := api.IsZero(api.Sub(tx.TxType, TxTypeBuyNft))
	isWithdrawNftTx := api.IsZero(api.Sub(tx.TxType, TxTypeWithdrawNft))

	// no need to verify signature transaction
	notNoSignatureTx := api.IsZero(api.Or(isEmptyTx, api.Or(api.Or(isRegisterZnsTx, isDepositTx), isDepositNftTx)))

	// get hash value from tx based on tx type
	// transfer tx
	hashVal := std.ComputeHashFromGenericTransferTx(tx.GenericTransferTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	// swap tx
	hashValCheck := std.ComputeHashFromSwapTx(tx.SwapTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isSwapTx, hashValCheck, hashVal)
	// add liquidity tx
	hashValCheck = std.ComputeHashFromAddLiquidityTx(tx.AddLiquidityTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isAddLiquidityTx, hashValCheck, hashVal)
	// remove liquidity tx
	hashValCheck = std.ComputeHashFromRemoveLiquidityTx(tx.RemoveLiquidityTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isRemoveLiquidityTx, hashValCheck, hashVal)
	// withdraw tx
	hashValCheck = std.ComputeHashFromWithdrawTx(tx.WithdrawTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isWithdrawTx, hashValCheck, hashVal)
	// mint nft tx
	hashValCheck = std.ComputeHashFromMintNftTx(tx.MintNftTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isMintNftTx, hashValCheck, hashVal)
	// set nft price tx
	hashValCheck = std.ComputeHashFromSetNftPriceTx(tx.SetNftPriceTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isSetNftPriceTx, hashValCheck, hashVal)
	// buy nft tx
	hashValCheck = std.ComputeHashFromBuyNftTx(tx.BuyNftTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isBuyNftTx, hashValCheck, hashVal)
	// withdraw nft tx
	hashValCheck = std.ComputeHashFromWithdrawNftTx(tx.WithdrawNftTxInfo, tx.AccountsInfoBefore[0].Nonce, hFunc)
	hashVal = api.Select(isWithdrawNftTx, hashValCheck, hashVal)
	hFunc.Reset()
	// verify signature
	err := std.VerifyEddsaSig(
		notNoSignatureTx,
		api,
		hFunc,
		hashVal,
		tx.AccountsInfoBefore[0].AccountPk,
		tx.Signature,
	)
	if err != nil {
		log.Println("[VerifyTx] invalid signature:", err)
		return err
	}

	for i := 0; i < NbAccountsPerTx; i++ {
		// verify account params - before & after
		CompareAccountBeforeAndAfterParams(api, tx.AccountsInfoBefore[i], tx.AccountsInfoAfter[i])
		// verify account asset node hash
		/*
			Index    Variable
			Balance  Variable
			AssetAId Variable
			AssetBId Variable
			AssetA   Variable
			AssetB   Variable
			LpAmount Variable
		*/
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			hFunc.Reset()
			hFunc.Write(
				tx.AccountsInfoBefore[i].AssetsInfo[j].AssetId,
				tx.AccountsInfoBefore[i].AssetsInfo[j].Balance,
			)
			assetNodeHash := hFunc.Sum()
			notNilAssetRoot := api.IsZero(api.IsZero(api.Sub(tx.AccountsInfoBefore[i].AccountAssetsRoot, nilHash)))
			std.IsVariableEqual(api, notNilAssetRoot, tx.MerkleProofsAccountAssetsBefore[i][j][0], assetNodeHash)
			// verify account asset merkle proof
			hFunc.Reset()
			std.VerifyMerkleProof(
				api,
				notNilAssetRoot,
				hFunc,
				tx.AccountsInfoBefore[i].AccountAssetsRoot,
				tx.MerkleProofsAccountAssetsBefore[i][j][:],
				tx.MerkleProofsHelperAccountAssetsBefore[i][j][:],
			)
		}
		// verify account liquidity node hash
		hFunc.Reset()
		hFunc.Write(
			tx.AccountsInfoBefore[i].LiquidityInfo.PairIndex,
			tx.AccountsInfoBefore[i].LiquidityInfo.AssetAId,
			tx.AccountsInfoBefore[i].LiquidityInfo.AssetAAmount,
			tx.AccountsInfoBefore[i].LiquidityInfo.AssetBId,
			tx.AccountsInfoBefore[i].LiquidityInfo.AssetBAmount,
			tx.AccountsInfoBefore[i].LiquidityInfo.LpAmount,
		)
		liquidityNodeHash := hFunc.Sum()
		notNilLiquidityRoot := api.IsZero(api.IsZero(api.Sub(tx.AccountsInfoBefore[i].AccountLiquidityRoot, nilHash)))
		std.IsVariableEqual(api, notNilLiquidityRoot, tx.MerkleProofsAccountLiquidityBefore[i][0], liquidityNodeHash)
		// verify account liquidity merkle proof
		hFunc.Reset()
		std.VerifyMerkleProof(
			api,
			notNilLiquidityRoot,
			hFunc,
			tx.AccountsInfoBefore[i].AccountNftRoot,
			tx.MerkleProofsAccountLiquidityBefore[i][:],
			tx.MerkleProofsHelperAccountLiquidityBefore[i][:],
		)
		// verify account nft node hash
		/*
			NftIndex       Variable
			CreatorIndex   Variable
			NftContentHash Variable
			AssetId        Variable
			AssetAmount    Variable
			NftL1Address      Variable
			NftTokenId      Variable
		*/
		hFunc.Reset()
		hFunc.Write(
			tx.AccountsInfoBefore[i].NftInfo.NftAssetId,
			tx.AccountsInfoBefore[i].NftInfo.NftIndex,
			tx.AccountsInfoBefore[i].NftInfo.CreatorIndex,
			tx.AccountsInfoBefore[i].NftInfo.NftContentHash,
			tx.AccountsInfoBefore[i].NftInfo.AssetId,
			tx.AccountsInfoBefore[i].NftInfo.AssetAmount,
			tx.AccountsInfoBefore[i].NftInfo.L1Address,
			tx.AccountsInfoBefore[i].NftInfo.L1TokenId,
		)
		nftNodeHash := hFunc.Sum()
		notNilNftRoot := api.IsZero(api.IsZero(api.Sub(tx.AccountsInfoBefore[i].AccountNftRoot, nilHash)))
		std.IsVariableEqual(api, notNilNftRoot, tx.MerkleProofsAccountNftBefore[i][0], nftNodeHash)
		// verify account nft merkle proof
		hFunc.Reset()
		std.VerifyMerkleProof(
			api,
			notNilNftRoot,
			hFunc,
			tx.AccountsInfoBefore[i].AccountNftRoot,
			tx.MerkleProofsAccountNftBefore[i][:],
			tx.MerkleProofsHelperAccountNftBefore[i][:],
		)
		// verify account node hash
		/*
			AccountIndex      Variable
			AccountName       Variable
			AccountPk         eddsa.PublicKey
			Nonce             Variable
			StateRoot         Variable
			AccountAssetsRoot Variable
			AccountNftRoot    Variable
		*/
		hFunc.Reset()
		hFunc.Write(
			tx.AccountsInfoBefore[i].AccountIndex,
			tx.AccountsInfoBefore[i].AccountName,
			tx.AccountsInfoBefore[i].AccountPk.A.X,
			tx.AccountsInfoBefore[i].AccountPk.A.Y,
			tx.AccountsInfoBefore[i].Nonce,
			tx.AccountsInfoBefore[i].AccountAssetsRoot,
			tx.AccountsInfoBefore[i].AccountNftRoot,
		)
		accountNodeHash := hFunc.Sum()
		notNilAccountRoot := api.IsZero(api.IsZero(api.Sub(tx.AccountRootBefore, nilHash)))
		std.IsVariableEqual(api, notNilAccountRoot, tx.MerkleProofsAccountBefore[i][0], accountNodeHash)
		// verify account merkle proof
		hFunc.Reset()
		std.VerifyMerkleProof(
			api,
			notNilAccountRoot,
			hFunc,
			tx.AccountRootBefore,
			tx.MerkleProofsAccountBefore[i][:],
			tx.MerkleProofsHelperAccountBefore[i][:],
		)
	}

	// verify transactions
	std.VerifyRegisterZnsTx(api, isRegisterZnsTx, tx.RegisterZnsTxInfo, tx.AccountsInfoBefore, tx.AccountsInfoAfter)
	std.VerifyDepositTx(api, isDepositTx, tx.DepositTxInfo, tx.AccountsInfoBefore)
	std.VerifyDepositNftTx(api, isDepositNftTx, nilHash, tx.DepositNftTxInfo, tx.AccountsInfoBefore, tx.AccountsInfoAfter)
	std.VerifyGenericTransferTx(api, isGenericTransferTx, nilHash, tx.GenericTransferTxInfo, tx.AccountsInfoBefore, tx.AccountsInfoAfter)
	std.VerifySwapTx(api, isSwapTx, tx.SwapTxInfo, tx.AccountsInfoBefore)
	std.VerifyAddLiquidityTx(api, isAddLiquidityTx, tx.AddLiquidityTxInfo, tx.AccountsInfoBefore)
	std.VerifyRemoveLiquidityTx(api, isRemoveLiquidityTx, tx.RemoveLiquidityTxInfo, tx.AccountsInfoBefore)
	std.VerifyWithdrawTx(api, isWithdrawTx, tx.WithdrawTxInfo, tx.AccountsInfoBefore)
	std.VerifyMintNftTx(api, isMintNftTx, nilHash, tx.MintNftTxInfo, tx.AccountsInfoBefore, tx.AccountsInfoAfter)
	std.VerifySetNftPriceTx(api, isSetNftPriceTx, tx.SetNftPriceTxInfo, tx.AccountsInfoBefore, tx.AccountsInfoAfter)
	std.VerifyBuyNftTx(api, isBuyNftTx, nilHash, tx.BuyNftTxInfo, tx.AccountsInfoBefore, tx.AccountsInfoAfter)
	std.VerifyWithdrawNftTx(api, isWithdrawNftTx, nilHash, tx.WithdrawNftTxInfo, tx.AccountsInfoBefore, tx.AccountsInfoAfter)
	// get deltas from tx
	deltas := GetAccountDeltasFromRegisterZns(api, tx.RegisterZnsTxInfo)
	// deposit
	deltasCheck := GetAccountDeltasFromDeposit(api, tx.DepositTxInfo)
	deltas = SelectDeltas(api, isDepositTx, deltasCheck, deltas)
	// deposit nft
	deltasCheck = GetAccountDeltasFromDepositNft(api, tx.DepositNftTxInfo)
	deltas = SelectDeltas(api, isDepositNftTx, deltasCheck, deltas)
	// generic transfer
	deltasCheck = GetAccountDeltasFromGenericTransfer(api, tx.GenericTransferTxInfo)
	deltas = SelectDeltas(api, isGenericTransferTx, deltasCheck, deltas)
	// swap
	deltasCheck = GetAccountDeltasFromSwap(api, tx.SwapTxInfo)
	deltas = SelectDeltas(api, isSwapTx, deltasCheck, deltas)
	// add liquidity
	deltasCheck = GetAccountDeltasFromAddLiquidity(api, tx.AddLiquidityTxInfo)
	deltas = SelectDeltas(api, isAddLiquidityTx, deltasCheck, deltas)
	// remove liquidity
	deltasCheck = GetAccountDeltasFromRemoveLiquidity(api, tx.RemoveLiquidityTxInfo)
	deltas = SelectDeltas(api, isRemoveLiquidityTx, deltasCheck, deltas)
	// withdraw
	deltasCheck = GetAccountDeltasFromWithdraw(api, tx.WithdrawTxInfo)
	deltas = SelectDeltas(api, isWithdrawTx, deltasCheck, deltas)
	// mint nft
	deltasCheck = GetAccountDeltasFromMintNft(api, tx.MintNftTxInfo)
	deltas = SelectDeltas(api, isMintNftTx, deltasCheck, deltas)
	// set nft price
	deltasCheck = GetAccountDeltasFromSetNftPrice(api, tx.SetNftPriceTxInfo)
	deltas = SelectDeltas(api, isSetNftPriceTx, deltasCheck, deltas)
	// buy nft
	deltasCheck = GetAccountDeltasFromBuyNft(api, tx.BuyNftTxInfo)
	deltas = SelectDeltas(api, isBuyNftTx, deltasCheck, deltas)
	// withdraw nft
	deltasCheck = GetAccountDeltasFromWithdrawNft(api, tx.WithdrawNftTxInfo)
	deltas = SelectDeltas(api, isWithdrawNftTx, deltasCheck, deltas)
	// update accounts
	tx.AccountsInfoBefore = UpdateAccounts(api, tx.AccountsInfoBefore, deltas)
	// verify updated account params
	std.CompareAccountsAfterUpdate(api, tx.AccountsInfoBefore, tx.AccountsInfoAfter)

	// check accounts after
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			// verify updated account asset node hash
			hFunc.Reset()
			hFunc.Write(
				tx.AccountsInfoAfter[i].AssetsInfo[j].AssetId,
				tx.AccountsInfoAfter[i].AssetsInfo[j].Balance,
			)
			assetNodeHash := hFunc.Sum()
			api.AssertIsEqual(tx.MerkleProofsAccountAssetsAfter[i][j][0], assetNodeHash)
			// verify updated account asset merkle proof
			hFunc.Reset()
			std.VerifyMerkleProof(
				api,
				1,
				hFunc,
				tx.AccountsInfoAfter[i].AccountAssetsRoot,
				tx.MerkleProofsAccountAssetsAfter[i][j][:],
				tx.MerkleProofsHelperAccountAssetsAfter[i][j][:],
			)
		}
		// verify account liquidity node hash
		hFunc.Reset()
		hFunc.Write(
			tx.AccountsInfoAfter[i].LiquidityInfo.PairIndex,
			tx.AccountsInfoAfter[i].LiquidityInfo.AssetAId,
			tx.AccountsInfoAfter[i].LiquidityInfo.AssetAAmount,
			tx.AccountsInfoAfter[i].LiquidityInfo.AssetBId,
			tx.AccountsInfoAfter[i].LiquidityInfo.AssetBAmount,
			tx.AccountsInfoAfter[i].LiquidityInfo.LpAmount,
		)
		liquidityNodeHash := hFunc.Sum()
		notNilLiquidityRoot := api.IsZero(api.IsZero(api.Sub(tx.AccountsInfoAfter[i].AccountLiquidityRoot, nilHash)))
		std.IsVariableEqual(api, notNilLiquidityRoot, tx.MerkleProofsAccountLiquidityAfter[i][0], liquidityNodeHash)
		// verify account liquidity merkle proof
		hFunc.Reset()
		std.VerifyMerkleProof(
			api,
			notNilLiquidityRoot,
			hFunc,
			tx.AccountsInfoAfter[i].AccountNftRoot,
			tx.MerkleProofsAccountLiquidityAfter[i][:],
			tx.MerkleProofsHelperAccountLiquidityAfter[i][:],
		)
		// verify updated account nft node hash
		hFunc.Reset()
		hFunc.Write(
			tx.AccountsInfoAfter[i].NftInfo.NftAssetId,
			tx.AccountsInfoAfter[i].NftInfo.NftIndex,
			tx.AccountsInfoAfter[i].NftInfo.CreatorIndex,
			tx.AccountsInfoAfter[i].NftInfo.NftContentHash,
			tx.AccountsInfoAfter[i].NftInfo.AssetId,
			tx.AccountsInfoAfter[i].NftInfo.AssetAmount,
			tx.AccountsInfoAfter[i].NftInfo.L1Address,
			tx.AccountsInfoAfter[i].NftInfo.L1TokenId,
		)
		nftNodeHash := hFunc.Sum()
		notNilNftRoot := api.IsZero(api.IsZero(api.Sub(tx.AccountsInfoAfter[i].AccountNftRoot, nilHash)))
		std.IsVariableEqual(api, notNilNftRoot, tx.MerkleProofsAccountNftAfter[i][0], nftNodeHash)
		// verify updated account nft merkle proof
		hFunc.Reset()
		std.VerifyMerkleProof(
			api,
			notNilNftRoot,
			hFunc,
			tx.AccountsInfoAfter[i].AccountNftRoot,
			tx.MerkleProofsAccountNftAfter[i][:],
			tx.MerkleProofsHelperAccountNftAfter[i][:],
		)

		// verify updated account node hash
		hFunc.Reset()
		hFunc.Write(
			tx.AccountsInfoAfter[i].AccountIndex,
			tx.AccountsInfoAfter[i].AccountName,
			tx.AccountsInfoAfter[i].AccountPk.A.X,
			tx.AccountsInfoAfter[i].AccountPk.A.Y,
			tx.AccountsInfoAfter[i].Nonce,
			tx.AccountsInfoAfter[i].AccountAssetsRoot,
			tx.AccountsInfoAfter[i].AccountNftRoot,
		)
		accountNodeHash := hFunc.Sum()
		api.AssertIsEqual(tx.MerkleProofsAccountAfter[i][0], accountNodeHash)
		// verify updated account merkle proof
		hFunc.Reset()
		std.VerifyMerkleProof(
			api,
			1,
			hFunc,
			tx.AccountRootAfter,
			tx.MerkleProofsAccountAfter[i][:],
			tx.MerkleProofsHelperAccountAfter[i][:],
		)
	}
	return nil
}

func SetTxWitness(oTx *Tx) (witness TxConstraints, err error) {
	witness.RegisterZnsTxInfo = std.EmptyRegisterZnsTxWitness()
	witness.DepositTxInfo = std.EmptyDepositTxWitness()
	witness.DepositNftTxInfo = std.EmptyDepositNftTxWitness()
	witness.GenericTransferTxInfo = std.EmptyGenericTransferTxWitness()
	witness.SwapTxInfo = std.EmptySwapTxWitness()
	witness.AddLiquidityTxInfo = std.EmptyAddLiquidityTxWitness()
	witness.RemoveLiquidityTxInfo = std.EmptyRemoveLiquidityTxWitness()
	witness.MintNftTxInfo = std.EmptyMintNftTxWitness()
	witness.SetNftPriceTxInfo = std.EmptySetNftPriceTxWitness()
	witness.BuyNftTxInfo = std.EmptyBuyNftTxWitness()
	witness.WithdrawTxInfo = std.EmptyWithdrawTxWitness()
	witness.WithdrawNftTxInfo = std.EmptyWithdrawNftTxWitness()
	switch oTx.TxType {
	case TxTypeEmptyTx:
		break
	case TxTypeRegisterZns:
		witness.RegisterZnsTxInfo = std.SetRegisterZnsTxWitness(oTx.RegisterZnsTxInfo)
		break
	case TxTypeDeposit:
		witness.DepositTxInfo = std.SetDepositTxWitness(oTx.DepositTxInfo)
		break
	case TxTypeDepositNft:
		witness.DepositNftTxInfo = std.SetDepositNftTxWitness(oTx.DepositNftTxInfo)
		break
	case TxTypeGenericTransfer:
		witness.GenericTransferTxInfo = std.SetGenericTransferTxWitness(oTx.GenericTransferTxInfo)
		break
	case TxTypeSwap:
		witness.SwapTxInfo = std.SetSwapTxWitness(oTx.SwapTxInfo)
		break
	case TxTypeAddLiquidity:
		witness.AddLiquidityTxInfo = std.SetAddLiquidityTxWitness(oTx.AddLiquidityTxInfo)
		break
	case TxTypeRemoveLiquidity:
		witness.RemoveLiquidityTxInfo = std.SetRemoveLiquidityTxWitness(oTx.RemoveLiquidityTxInfo)
		break
	case TxTypeWithdraw:
		witness.WithdrawTxInfo = std.SetWithdrawTxWitness(oTx.WithdrawTxInfo)
		break
	case TxTypeMintNft:
		witness.MintNftTxInfo = std.SetMintNftTxWitness(oTx.MintNftTxInfo)
		break
	case TxTypeSetNftPrice:
		witness.SetNftPriceTxInfo = std.SetSetNftPriceTxWitness(oTx.SetNftPriceTxInfo)
		break
	case TxTypeBuyNft:
		witness.BuyNftTxInfo = std.SetBuyNftTxWitness(oTx.BuyNftTxInfo)
		break
	case TxTypeWithdrawNft:
		witness.WithdrawNftTxInfo = std.SetWithdrawNftTxWitness(oTx.WithdrawNftTxInfo)
		break
	default:
		log.Println("[SetTxWitness] invalid oTx type")
		return witness, errors.New("[SetTxWitness] invalid oTx type")
	}
	// set common account & merkle parts
	// account root before
	witness.AccountRootBefore = oTx.AccountRootBefore
	// account root after
	witness.AccountRootAfter = oTx.AccountRootAfter
	// account before info, size is 4
	for i := 0; i < NbAccountsPerTx; i++ {
		// accounts info before
		witness.AccountsInfoBefore[i], err = std.SetAccountWitness(oTx.AccountsInfoBefore[i])
		if err != nil {
			log.Println("[SetTxWitness] err info:", err)
			return witness, err
		}
		// accounts info after
		witness.AccountsInfoAfter[i], err = std.SetAccountWitness(oTx.AccountsInfoAfter[i])
		if err != nil {
			log.Println("[SetTxWitness] err info:", err)
			return witness, err
		}
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			for k := 0; k < AssetMerkleLevels; k++ {
				if k != AssetMerkleHelperLevels {
					// account assets before
					witness.MerkleProofsHelperAccountAssetsBefore[i][j][k] = oTx.MerkleProofsHelperAccountAssetsBefore[i][j][k]
					// account assets after
					witness.MerkleProofsHelperAccountAssetsAfter[i][j][k] = oTx.MerkleProofsHelperAccountAssetsAfter[i][j][k]
					// liquidity asset before
					witness.MerkleProofsHelperAccountLiquidityBefore[i][j] = oTx.MerkleProofsHelperAccountLiquidityBefore[i][j]
					// liquidity asset after
					witness.MerkleProofsHelperAccountLiquidityAfter[i][j] = oTx.MerkleProofsHelperAccountLiquidityAfter[i][j]
				}
				// account assets before
				witness.MerkleProofsAccountAssetsBefore[i][j][k] = oTx.MerkleProofsAccountAssetsBefore[i][j][k]
				// account assets after
				witness.MerkleProofsAccountAssetsAfter[i][j][k] = oTx.MerkleProofsAccountAssetsAfter[i][j][k]
			}
		}
		for j := 0; j < NftMerkleLevels; j++ {
			if j != NftMerkleHelperLevels {
				// nft assets before
				witness.MerkleProofsHelperAccountNftBefore[i][j] = oTx.MerkleProofsHelperAccountNftBefore[i][j]
				// nft assets after
				witness.MerkleProofsHelperAccountNftAfter[i][j] = oTx.MerkleProofsHelperAccountNftAfter[i][j]
			}
			// liquidity asset before
			witness.MerkleProofsAccountLiquidityBefore[i][j] = oTx.MerkleProofsAccountLiquidityBefore[i][j]
			// liquidity asset after
			witness.MerkleProofsAccountLiquidityAfter[i][j] = oTx.MerkleProofsAccountLiquidityAfter[i][j]
			// nft assets before
			witness.MerkleProofsAccountNftBefore[i][j] = oTx.MerkleProofsAccountNftBefore[i][j]
			// nft assets after
			witness.MerkleProofsAccountNftAfter[i][j] = oTx.MerkleProofsAccountNftAfter[i][j]
		}
		for j := 0; j < AccountMerkleLevels; j++ {
			if j != AccountMerkleHelperLevels {
				// account before
				witness.MerkleProofsHelperAccountBefore[i][j] = oTx.MerkleProofsHelperAccountBefore[i][j]
				// account after
				witness.MerkleProofsHelperAccountAfter[i][j] = oTx.MerkleProofsHelperAccountAfter[i][j]
			}
			// account before
			witness.MerkleProofsAccountBefore[i][j] = oTx.MerkleProofsAccountBefore[i][j]
			// account after
			witness.MerkleProofsAccountAfter[i][j] = oTx.MerkleProofsAccountAfter[i][j]
		}
	}
	return witness, nil
}
