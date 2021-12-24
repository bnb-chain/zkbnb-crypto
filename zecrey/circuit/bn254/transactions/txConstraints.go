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
	"encoding/hex"
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"log"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/zecrey/circuit/bn254/std"
)

type TxConstraints struct {
	// tx type
	TxType Variable
	// deposit info
	DepositTxInfo DepositOrLockTxConstraints
	// lock info
	LockTxInfo DepositOrLockTxConstraints
	// unlock proof
	UnlockProof UnlockProofConstraints
	// transfer proof
	TransferProof TransferProofConstraints
	// swap proof
	SwapProof SwapProofConstraints
	// add liquidity proof
	AddLiquidityProof AddLiquidityProofConstraints
	// remove liquidity proof
	RemoveLiquidityProof RemoveLiquidityProofConstraints
	// withdraw proof
	WithdrawProof WithdrawProofConstraints
	// common verification part
	// range proofs
	RangeProofs [MaxRangeProofCount]CtRangeProofConstraints
	// account root before
	AccountRootBefore Variable
	// account before info, size is 4
	AccountsInfoBefore [NbAccountsPerTx]AccountConstraints
	// before account merkle proof
	MerkleProofsAccountBefore       [NbAccountsPerTx][AccountMerkleLevels]Variable
	MerkleProofsHelperAccountBefore [NbAccountsPerTx][AccountMerkleHelperLevels]Variable
	// before account asset merkle proof
	MerkleProofsAccountAssetsBefore       [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels]Variable
	MerkleProofsHelperAccountAssetsBefore [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleHelperLevels]Variable
	// before account asset lock merkle proof
	MerkleProofsAccountLockedAssetsBefore       [NbAccountsPerTx][LockedAssetMerkleLevels]Variable
	MerkleProofsHelperAccountLockedAssetsBefore [NbAccountsPerTx][LockedAssetMerkleHelperLevels]Variable
	// before account liquidity merkle proof
	MerkleProofsAccountLiquidityBefore       [NbAccountsPerTx][LiquidityMerkleLevels]Variable
	MerkleProofsHelperAccountLiquidityBefore [NbAccountsPerTx][LiquidityMerkleHelperLevels]Variable
	// account root after
	AccountRootAfter Variable
	// account after info, size is 4
	AccountsInfoAfter [NbAccountsPerTx]AccountConstraints
	// after account merkle proof
	MerkleProofsAccountAfter       [NbAccountsPerTx][AccountMerkleLevels]Variable
	MerkleProofsHelperAccountAfter [NbAccountsPerTx][AccountMerkleHelperLevels]Variable
	// after account asset merkle proof
	MerkleProofsAccountAssetsAfter       [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleLevels]Variable
	MerkleProofsHelperAccountAssetsAfter [NbAccountsPerTx][NbAccountAssetsPerAccount][AssetMerkleHelperLevels]Variable
	// after account asset lock merkle proof
	MerkleProofsAccountLockedAssetsAfter       [NbAccountsPerTx][LockedAssetMerkleLevels]Variable
	MerkleProofsHelperAccountLockedAssetsAfter [NbAccountsPerTx][LockedAssetMerkleHelperLevels]Variable
	// after account liquidity merkle proof
	MerkleProofsAccountLiquidityAfter       [NbAccountsPerTx][LiquidityMerkleLevels]Variable
	MerkleProofsHelperAccountLiquidityAfter [NbAccountsPerTx][LiquidityMerkleHelperLevels]Variable
}

func (circuit TxConstraints) Define(curveID ecc.ID, api frontend.API) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	// mimc
	hFunc, err := mimc.NewMiMC(zmimc.SEED, curveID, api)
	if err != nil {
		return err
	}

	H := Point{
		X: api.Constant(std.HX),
		Y: api.Constant(std.HY),
	}
	tool := std.NewEccTool(api, params)
	nilHashBytes, err := hex.DecodeString("01ef55cdf3b9b0d65e6fb6317f79627534d971fd96c811281af618c0028d5e7a")
	if err != nil {
		return err
	}
	nilHash := api.Constant(nilHashBytes)
	VerifyTransaction(tool, api, circuit, hFunc, H, nilHash)
	return nil
}

func VerifyTransaction(
	tool *std.EccTool,
	api API,
	tx TxConstraints,
	hFunc MiMC,
	h Point,
	nilHash Variable,
) {
	// txType constants
	txTypeNoop := api.Constant(uint64(TxTypeNoop))
	txTypeDeposit := api.Constant(uint64(TxTypeDeposit))
	txTypeLock := api.Constant(uint64(TxTypeLock))
	txTypeUnlock := api.Constant(uint64(TxTypeUnlock))
	txTypeTransfer := api.Constant(uint64(TxTypeTransfer))
	txTypeSwap := api.Constant(uint64(TxTypeSwap))
	txTypeAddLiquidity := api.Constant(uint64(TxTypeAddLiquidity))
	txTypeRemoveLiquidity := api.Constant(uint64(TxTypeRemoveLiquidity))
	txTypeWithdraw := api.Constant(uint64(TxTypeWithdraw))

	// compute tx type
	isNoopTx := api.IsZero(api.Sub(tx.TxType, txTypeNoop))
	isDepositTx := api.IsZero(api.Sub(tx.TxType, txTypeDeposit))
	tx.DepositTxInfo.IsEnabled = isDepositTx
	isLockTx := api.IsZero(api.Sub(tx.TxType, txTypeLock))
	tx.LockTxInfo.IsEnabled = isLockTx
	isUnlockTx := api.IsZero(api.Sub(tx.TxType, txTypeUnlock))
	tx.UnlockProof.IsEnabled = isUnlockTx
	isTransferTx := api.IsZero(api.Sub(tx.TxType, txTypeTransfer))
	tx.TransferProof.IsEnabled = isTransferTx
	isSwapTx := api.IsZero(api.Sub(tx.TxType, txTypeSwap))
	tx.SwapProof.IsEnabled = isSwapTx
	isAddLiquidityTx := api.IsZero(api.Sub(tx.TxType, txTypeAddLiquidity))
	tx.AddLiquidityProof.IsEnabled = isAddLiquidityTx
	isRemoveLiquidityTx := api.IsZero(api.Sub(tx.TxType, txTypeRemoveLiquidity))
	tx.RemoveLiquidityProof.IsEnabled = isRemoveLiquidityTx
	isWithdrawTx := api.IsZero(api.Sub(tx.TxType, txTypeWithdraw))
	tx.WithdrawProof.IsEnabled = isWithdrawTx

	isCheckAccount := api.IsZero(isNoopTx)
	// verify range proofs
	for i, rangeProof := range tx.RangeProofs {
		// set range proof is true
		isNoRangeTx := api.Or(isDepositTx, isLockTx)
		isEnabled := api.IsZero(isNoRangeTx)
		rangeProof.IsEnabled = isEnabled
		std.VerifyCtRangeProof(tool, api, rangeProof, hFunc)
		hFunc.Reset()
		tx.TransferProof.SubProofs[i].Y = rangeProof.A
	}
	// set T or Y
	// unlock proof
	tx.UnlockProof.T_fee = tx.RangeProofs[0].A
	// transfer proof
	for i := 0; i < NbTransferCount; i++ {
		tx.TransferProof.SubProofs[i].T = tx.RangeProofs[i].A
	}
	// swap proof
	tx.SwapProof.T_uA = tx.RangeProofs[0].A
	tx.SwapProof.T_fee = tx.RangeProofs[1].A
	// add liquidity proof
	tx.AddLiquidityProof.T_uA = tx.RangeProofs[0].A
	tx.AddLiquidityProof.T_uB = tx.RangeProofs[1].A
	tx.AddLiquidityProof.T_fee = tx.RangeProofs[2].A
	// remove liquidity proof
	tx.RemoveLiquidityProof.T_uLP = tx.RangeProofs[0].A
	tx.RemoveLiquidityProof.T_fee = tx.RangeProofs[1].A
	// withdraw proof
	tx.WithdrawProof.T = tx.RangeProofs[0].A
	tx.WithdrawProof.T_fee = tx.RangeProofs[1].A
	// check if it is nil account root
	//notNilAccount := api.IsZero(api.IsZero(api.Sub(tx.AccountRootBefore, nilHash)))
	// verify account before
	for i := 0; i < NbAccountsPerTx; i++ {
		// verify accounts before & after params
		// check if it is nil account
		notNilAccountState := api.IsZero(api.IsZero(api.Sub(tx.AccountsInfoBefore[i].StateRoot, nilHash)))
		std.IsVariableEqual(api, notNilAccountState, tx.AccountsInfoBefore[i].AccountIndex, tx.AccountsInfoAfter[i].AccountIndex)
		std.IsVariableEqual(api, notNilAccountState, tx.AccountsInfoBefore[i].AccountName, tx.AccountsInfoAfter[i].AccountName)
		std.IsPointEqual(api, notNilAccountState, tx.AccountsInfoBefore[i].AccountPk, tx.AccountsInfoAfter[i].AccountPk)
		// check state root
		hFunc.Write(
			tx.AccountsInfoBefore[i].AccountAssetsRoot,
			tx.AccountsInfoBefore[i].AccountLockedAssetsRoot,
			tx.AccountsInfoBefore[i].AccountLiquidityRoot,
		)
		accountRootCheck := hFunc.Sum()
		std.IsVariableEqual(api, notNilAccountState, accountRootCheck, tx.AccountsInfoBefore[i].StateRoot)
		hFunc.Reset()
		// check account hash
		hFunc.Write(
			tx.AccountsInfoBefore[i].AccountIndex,
			tx.AccountsInfoBefore[i].AccountName,
		)
		std.WritePointIntoBuf(&hFunc, tx.AccountsInfoBefore[i].AccountPk)
		hFunc.Write(tx.AccountsInfoBefore[i].StateRoot)
		accountHashCheck := hFunc.Sum()
		accountHash := api.Select(notNilAccountState, nilHash, accountHashCheck)
		std.IsVariableEqual(api, isCheckAccount, accountHash, tx.MerkleProofsAccountBefore[i][0])
		hFunc.Reset()
		// verify account asset root
		isNilAssetRoot := api.IsZero(api.Sub(tx.AccountsInfoBefore[i].AccountAssetsRoot, nilHash))
		notNilAssetRootAndNotLockTx := api.IsZero(api.Or(isNilAssetRoot, isLockTx))
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			std.VerifyMerkleProof(
				api, notNilAssetRootAndNotLockTx, hFunc,
				tx.AccountsInfoBefore[i].AccountAssetsRoot,
				tx.MerkleProofsAccountAssetsBefore[i][j][:], tx.MerkleProofsHelperAccountAssetsBefore[i][j][:])
			hFunc.Reset()
			// verify account asset before & after params
			std.IsVariableEqual(
				api, notNilAssetRootAndNotLockTx,
				tx.AccountsInfoBefore[i].AssetsInfo[j].AssetId, tx.AccountsInfoAfter[i].AssetsInfo[j].AssetId)
		}
		// verify account locked asset root
		isNilLockedAssetRoot := api.IsZero(api.Sub(tx.AccountsInfoBefore[i].LockedAssetInfo, nilHash))
		isLockRelatedTx := api.Or(isLockTx, isUnlockTx)
		notNilLockedAssetRootAndNotLockRelatedTx := api.IsZero(api.Or(isNilLockedAssetRoot, isLockRelatedTx))
		std.VerifyMerkleProof(
			api, notNilLockedAssetRootAndNotLockRelatedTx, hFunc,
			tx.AccountsInfoBefore[i].AccountLockedAssetsRoot,
			tx.MerkleProofsAccountLockedAssetsBefore[i][:], tx.MerkleProofsHelperAccountLockedAssetsBefore[i][:])
		hFunc.Reset()
		// verify account locked asset before & after params
		std.IsVariableEqual(
			api, notNilLockedAssetRootAndNotLockRelatedTx,
			tx.AccountsInfoBefore[i].LockedAssetInfo.ChainId, tx.AccountsInfoAfter[i].LockedAssetInfo.ChainId)
		std.IsVariableEqual(
			api, notNilLockedAssetRootAndNotLockRelatedTx,
			tx.AccountsInfoBefore[i].LockedAssetInfo.AssetId, tx.AccountsInfoAfter[i].LockedAssetInfo.AssetId)
		// verify account liquidity root
		isNilAccountLiquidityRoot := api.IsZero(api.Sub(tx.AccountsInfoBefore[i].AccountLiquidityRoot, nilHash))
		isLiquidityRelatedTx := api.Or(api.Or(isSwapTx, isAddLiquidityTx), isRemoveLiquidityTx)
		isNilAccountLiquidityRootAndNotLiquidityRelatedTx := api.IsZero(api.Or(isNilAccountLiquidityRoot, isLiquidityRelatedTx))
		std.VerifyMerkleProof(
			api, isNilAccountLiquidityRootAndNotLiquidityRelatedTx, hFunc,
			tx.AccountsInfoBefore[i].AccountLiquidityRoot,
			tx.MerkleProofsAccountLiquidityBefore[i][:], tx.MerkleProofsHelperAccountLiquidityBefore[i][:])
		hFunc.Reset()
		// verify account liquidity before & after params
		std.IsVariableEqual(
			api, isNilAccountLiquidityRootAndNotLiquidityRelatedTx,
			tx.AccountsInfoBefore[i].LiquidityInfo.PairIndex, tx.AccountsInfoAfter[i].LiquidityInfo.PairIndex)
		// verify account root
		std.VerifyMerkleProof(
			api, notNilAccountState, hFunc,
			tx.AccountRootBefore,
			tx.MerkleProofsAccountBefore[i][:], tx.MerkleProofsHelperAccountBefore[i][:])
		hFunc.Reset()
	}

	// verify proofs
	var (
		c, cCheck               Variable
		pkProofs, pkProofsCheck [MaxRangeProofCount]std.CommonPkProof
		tProofs, tProofsCheck   [MaxRangeProofCount]std.CommonTProof
	)

	// verify unlock proof
	// set public data
	// set account info
	tx.UnlockProof.ChainId = tx.AccountsInfoBefore[UnlockFromAccount].LockedAssetInfo.ChainId
	tx.UnlockProof.AssetId = tx.AccountsInfoBefore[UnlockFromAccount].LockedAssetInfo.AssetId
	tx.UnlockProof.Pk = tx.AccountsInfoBefore[UnlockFromAccount].AccountPk
	tx.UnlockProof.Balance = tx.AccountsInfoBefore[UnlockFromAccount].LockedAssetInfo.LockedAmount
	// fee info
	tx.UnlockProof.C_fee = tx.AccountsInfoBefore[UnlockFromAccount].AssetsInfo[UnlockFromAccountGasAsset].BalanceEnc
	tx.UnlockProof.GasFeeAssetId = tx.AccountsInfoBefore[UnlockFromAccount].AssetsInfo[UnlockFromAccountGasAsset].AssetId
	c, pkProofs, tProofs = std.VerifyUnlockProof(tool, api, &tx.UnlockProof, hFunc, h)
	hFunc.Reset()

	// verify transfer proof
	// set public data
	// set account info
	tx.TransferProof.AssetId = tx.AccountsInfoBefore[TransferAccountA].AssetsInfo[TransferAccountTransferAsset].AssetId
	for i := 0; i < NbTransferCount; i++ {
		tx.TransferProof.SubProofs[i].Pk = tx.AccountsInfoBefore[i].AccountPk
		tx.TransferProof.SubProofs[i].C = tx.AccountsInfoBefore[i].AssetsInfo[TransferAccountTransferAsset].BalanceEnc
	}
	cCheck, pkProofsCheck, tProofsCheck = std.VerifyTransferProof(tool, api, &tx.TransferProof, hFunc, h)
	hFunc.Reset()
	c, pkProofs, tProofs = SelectCommonPart(api, isTransferTx, cCheck, c, pkProofsCheck, pkProofs, tProofsCheck, tProofs)

	// verify swap proof
	// set public data
	// set account info
	tx.SwapProof.C_uA = tx.AccountsInfoBefore[SwapFromAccount].AssetsInfo[SwapFromAccountAssetA].BalanceEnc
	tx.SwapProof.Pk_u = tx.AccountsInfoBefore[SwapFromAccount].AccountPk
	tx.SwapProof.AssetAId = tx.AccountsInfoBefore[SwapPoolAccount].LiquidityInfo.AssetAId
	tx.SwapProof.AssetBId = tx.AccountsInfoBefore[SwapPoolAccount].LiquidityInfo.AssetBId
	tx.SwapProof.Pk_pool = tx.AccountsInfoBefore[SwapPoolAccount].AccountPk
	tx.SwapProof.B_poolA = tx.AccountsInfoBefore[SwapPoolAccount].LiquidityInfo.AssetA
	tx.SwapProof.B_poolB = tx.AccountsInfoBefore[SwapPoolAccount].LiquidityInfo.AssetB
	tx.SwapProof.Pk_treasury = tx.AccountsInfoBefore[SwapTreasuryAccount].AccountPk
	// fee info
	tx.SwapProof.C_fee = tx.AccountsInfoBefore[SwapFromAccount].AssetsInfo[SwapFromAccountGasAsset].BalanceEnc
	tx.SwapProof.GasFeeAssetId = tx.AccountsInfoBefore[SwapFromAccount].AssetsInfo[SwapFromAccountGasAsset].AssetId
	cCheck, pkProofsCheck, tProofsCheck = std.VerifySwapProof(tool, api, &tx.SwapProof, hFunc, h)
	hFunc.Reset()
	c, pkProofs, tProofs = SelectCommonPart(api, isSwapTx, cCheck, c, pkProofsCheck, pkProofs, tProofsCheck, tProofs)

	// verify add liquidity proof
	// set public data
	// set account info
	tx.AddLiquidityProof.C_uA = tx.AccountsInfoBefore[AddLiquidityFromAccount].AssetsInfo[AddLiquidityFromAccountAssetA].BalanceEnc
	tx.AddLiquidityProof.C_uB = tx.AccountsInfoBefore[AddLiquidityFromAccount].AssetsInfo[AddLiquidityFromAccountAssetB].BalanceEnc
	tx.AddLiquidityProof.Pk_u = tx.AccountsInfoBefore[AddLiquidityFromAccount].AccountPk
	tx.AddLiquidityProof.AssetAId = tx.AccountsInfoBefore[AddLiquidityPoolAccount].LiquidityInfo.AssetAId
	tx.AddLiquidityProof.AssetBId = tx.AccountsInfoBefore[AddLiquidityPoolAccount].LiquidityInfo.AssetBId
	tx.AddLiquidityProof.Pk_pool = tx.AccountsInfoBefore[AddLiquidityPoolAccount].AccountPk
	tx.AddLiquidityProof.B_poolA = tx.AccountsInfoBefore[AddLiquidityPoolAccount].LiquidityInfo.AssetA
	tx.AddLiquidityProof.B_poolB = tx.AccountsInfoBefore[AddLiquidityPoolAccount].LiquidityInfo.AssetB
	// fee info
	tx.AddLiquidityProof.C_fee = tx.AccountsInfoBefore[AddLiquidityFromAccount].AssetsInfo[AddLiquidityFromAccountGasAsset].BalanceEnc
	tx.AddLiquidityProof.GasFeeAssetId = tx.AccountsInfoBefore[AddLiquidityFromAccount].AssetsInfo[AddLiquidityFromAccountGasAsset].AssetId
	cCheck, pkProofsCheck, tProofsCheck = std.VerifyAddLiquidityProof(tool, api, &tx.AddLiquidityProof, hFunc, h)
	hFunc.Reset()
	c, pkProofs, tProofs = SelectCommonPart(api, isAddLiquidityTx, cCheck, c, pkProofsCheck, pkProofs, tProofsCheck, tProofs)

	// verify remove liquidity proof
	// set public data
	// set account info
	tx.RemoveLiquidityProof.C_u_LP = tx.AccountsInfoBefore[RemoveLiquidityFromAccount].LiquidityInfo.LpEnc
	tx.RemoveLiquidityProof.Pk_u = tx.AccountsInfoBefore[RemoveLiquidityFromAccount].AccountPk
	tx.RemoveLiquidityProof.AssetAId = tx.AccountsInfoBefore[RemoveLiquidityPoolAccount].LiquidityInfo.AssetAId
	tx.RemoveLiquidityProof.AssetBId = tx.AccountsInfoBefore[RemoveLiquidityPoolAccount].LiquidityInfo.AssetBId
	tx.RemoveLiquidityProof.Pk_pool = tx.AccountsInfoBefore[RemoveLiquidityPoolAccount].AccountPk
	tx.RemoveLiquidityProof.B_pool_A = tx.AccountsInfoBefore[RemoveLiquidityPoolAccount].LiquidityInfo.AssetA
	tx.RemoveLiquidityProof.B_pool_B = tx.AccountsInfoBefore[RemoveLiquidityPoolAccount].LiquidityInfo.AssetB
	// fee info
	tx.RemoveLiquidityProof.C_fee = tx.AccountsInfoBefore[RemoveLiquidityFromAccount].AssetsInfo[RemoveLiquidityFromAccountGasAsset].BalanceEnc
	tx.RemoveLiquidityProof.GasFeeAssetId = tx.AccountsInfoBefore[RemoveLiquidityFromAccount].AssetsInfo[RemoveLiquidityFromAccountGasAsset].AssetId
	cCheck, pkProofsCheck, tProofsCheck = std.VerifyRemoveLiquidityProof(tool, api, &tx.RemoveLiquidityProof, hFunc, h)
	hFunc.Reset()
	c, pkProofs, tProofs = SelectCommonPart(api, isRemoveLiquidityTx, cCheck, c, pkProofsCheck, pkProofs, tProofsCheck, tProofs)

	// verify withdraw proof
	// set public data
	// set account info
	tx.WithdrawProof.AssetId = tx.AccountsInfoBefore[WithdrawFromAccount].AssetsInfo[WithdrawFromAccountAsset].AssetId
	tx.WithdrawProof.Pk = tx.AccountsInfoBefore[WithdrawFromAccount].AccountPk
	// fee info
	tx.WithdrawProof.C_fee = tx.AccountsInfoBefore[WithdrawFromAccount].AssetsInfo[WithdrawFromAccountGasAsset].BalanceEnc
	tx.WithdrawProof.GasFeeAssetId = tx.AccountsInfoBefore[WithdrawFromAccount].AssetsInfo[WithdrawFromAccountGasAsset].AssetId
	cCheck, pkProofsCheck, tProofsCheck = std.VerifyWithdrawProof(tool, api, &tx.WithdrawProof, hFunc, h)
	hFunc.Reset()
	c, pkProofs, tProofs = SelectCommonPart(api, isWithdrawTx, cCheck, c, pkProofsCheck, pkProofs, tProofsCheck, tProofs)
	enabled := api.Constant(1)
	for i := 0; i < MaxRangeProofCount; i++ {
		// pk proof
		l1 := tool.ScalarBaseMul(pkProofs[i].Z_sk_u)
		r1 := tool.Add(pkProofs[i].A_pk_u, tool.ScalarMul(pkProofs[i].Pk_u, c))
		std.IsPointEqual(api, enabled, l1, r1)
		// T proof
		// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
		l2 := tool.Add(tool.ScalarBaseMul(tProofs[i].Z_bar_r), tool.ScalarMul(tProofs[i].C_PrimeNeg.CL, pkProofs[i].Z_sk_uInv))
		r2 := tool.Add(tProofs[i].A_T_C_RPrimeInv, tool.ScalarMul(tool.Add(tProofs[i].T, tProofs[i].C_PrimeNeg.CR), c))
		std.IsPointEqual(api, enabled, l2, r2)
	}

	// check if the after account info is correct
	// collect deltas from proof
	deltas := GetAccountDeltasFromUnlockProof(api, tool, tx.UnlockProof)
	deltasCheck := GetAccountDeltasFromTransferProof(api, tool, tx.TransferProof)
	deltas = SelectDeltas(api, isTransferTx, deltasCheck, deltas)
	deltasCheck = GetAccountDeltasFromSwapProof(api, tool, tx.SwapProof, tx.AccountsInfoBefore[SwapPoolAccount])
	deltas = SelectDeltas(api, isTransferTx, deltasCheck, deltas)
	deltasCheck = GetAccountDeltasFromAddLiquidityProof(api, tool, tx.AddLiquidityProof, tx.AccountsInfoBefore[AddLiquidityPoolAccount])
	deltas = SelectDeltas(api, isTransferTx, deltasCheck, deltas)
	deltasCheck = GetAccountDeltasFromRemoveLiquidityProof(api, tool, tx.RemoveLiquidityProof, tx.AccountsInfoBefore[RemoveLiquidityPoolAccount])
	deltas = SelectDeltas(api, isTransferTx, deltasCheck, deltas)
	deltasCheck = GetAccountDeltasFromWithdrawProof(api, tool, tx.WithdrawProof)
	deltas = SelectDeltas(api, isTransferTx, deltasCheck, deltas)
	// update account before and check if equal to account after
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			// verify account asset
			tx.AccountsInfoBefore[i].AssetsInfo[j].BalanceEnc =
				tool.EncAdd(
					tx.AccountsInfoBefore[i].AssetsInfo[j].BalanceEnc,
					deltas[i].AssetsDeltaInfo[j],
				)
			std.IsElGamalEncEqual(
				api, isCheckAccount,
				tx.AccountsInfoBefore[i].AssetsInfo[j].BalanceEnc, tx.AccountsInfoAfter[i].AssetsInfo[j].BalanceEnc)
		}
		// verify locked asset
		tx.AccountsInfoBefore[i].LockedAssetInfo.LockedAmount = api.Add(tx.AccountsInfoBefore[i].LockedAssetInfo.LockedAmount, deltas[i].LockedAssetDeltaInfo)
		std.IsVariableEqual(
			api, isCheckAccount,
			tx.AccountsInfoBefore[i].LockedAssetInfo.LockedAmount, tx.AccountsInfoAfter[i].LockedAssetInfo.LockedAmount,
		)
		// verify liquidity asset
		tx.AccountsInfoBefore[i].LiquidityInfo = ComputeNewLiquidityConstraints(
			api, tool,
			tx.AccountsInfoBefore[i].LiquidityInfo, deltas[i].LiquidityDeltaInfo,
		)
		IsAccountLiquidityConstraintsEqual(
			api, isCheckAccount,
			tx.AccountsInfoBefore[i].LiquidityInfo, tx.AccountsInfoAfter[i].LiquidityInfo,
		)
	}
	// verify account after
	for i := 0; i < NbAccountsPerTx; i++ {
		// check state root
		hFunc.Write(
			tx.AccountsInfoAfter[i].AccountAssetsRoot,
			tx.AccountsInfoAfter[i].AccountLockedAssetsRoot,
			tx.AccountsInfoAfter[i].AccountLiquidityRoot,
		)
		stateRootCheck := hFunc.Sum()
		std.IsVariableEqual(api, isCheckAccount, stateRootCheck, tx.AccountsInfoAfter[i].StateRoot)
		hFunc.Reset()
		// check account hash
		hFunc.Write(
			tx.AccountsInfoAfter[i].AccountIndex,
			tx.AccountsInfoAfter[i].AccountName,
		)
		std.WritePointIntoBuf(&hFunc, tx.AccountsInfoAfter[i].AccountPk)
		hFunc.Write(tx.AccountsInfoAfter[i].StateRoot)
		accountHashCheck := hFunc.Sum()
		std.IsVariableEqual(api, isCheckAccount, accountHashCheck, tx.MerkleProofsAccountAfter[i][0])
		hFunc.Reset()
		// verify account asset root
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			std.VerifyMerkleProof(
				api, isCheckAccount, hFunc,
				tx.AccountsInfoAfter[i].AccountAssetsRoot,
				tx.MerkleProofsAccountAssetsAfter[i][j][:], tx.MerkleProofsHelperAccountAssetsAfter[i][j][:])
			hFunc.Reset()
		}
		// verify account locked asset root
		std.VerifyMerkleProof(
			api, isCheckAccount, hFunc,
			tx.AccountsInfoAfter[i].AccountLockedAssetsRoot,
			tx.MerkleProofsAccountLockedAssetsAfter[i][:], tx.MerkleProofsHelperAccountLockedAssetsAfter[i][:])
		hFunc.Reset()
		// verify account liquidity root
		std.VerifyMerkleProof(
			api, isCheckAccount, hFunc,
			tx.AccountsInfoAfter[i].AccountLiquidityRoot,
			tx.MerkleProofsAccountLiquidityAfter[i][:], tx.MerkleProofsHelperAccountLiquidityAfter[i][:])
		hFunc.Reset()
		// verify account root
		std.VerifyMerkleProof(
			api, isCheckAccount, hFunc,
			tx.AccountRootAfter,
			tx.MerkleProofsAccountAfter[i][:], tx.MerkleProofsHelperAccountAfter[i][:])
		hFunc.Reset()
	}

}

func SetTxWitness(oTx *Tx) (witness TxConstraints, err error) {
	oproof := oTx.OProof
	txType := oTx.TxType
	isEnabled := true
	switch txType {
	case TxTypeNoop:
		// set witness
		witness.TxType.Assign(uint64(txType))
		witness.DepositTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.LockTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.UnlockProof = std.SetEmptyUnlockProofWitness()
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = std.SetEmptySwapProofWitness()
		witness.AddLiquidityProof = std.SetEmptyAddLiquidityProofWitness()
		witness.RemoveLiquidityProof = std.SetEmptyRemoveLiquidityProofWitness()
		witness.WithdrawProof = std.SetEmptyWithdrawProofWitness()
		witness.RangeProofs[0] = std.SetEmptyCtRangeProofWitness()
		witness.RangeProofs[1] = std.SetEmptyCtRangeProofWitness()
		witness.RangeProofs[2] = std.SetEmptyCtRangeProofWitness()
		break
	case TxTypeDeposit:
		// convert to special proof
		tx, b := oproof.(*DepositOrLockTx)
		if !b {
			log.Println("[SetTxWitness] unable to convert proof to special type")
			return witness, errors.New("[SetTxWitness] unable to convert proof to special type")
		}
		// set witness
		witness.TxType.Assign(uint64(txType))
		witness.DepositTxInfo, err = std.SetDepositOrLockWitness(tx, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.UnlockProof = std.SetEmptyUnlockProofWitness()
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = std.SetEmptySwapProofWitness()
		witness.AddLiquidityProof = std.SetEmptyAddLiquidityProofWitness()
		witness.RemoveLiquidityProof = std.SetEmptyRemoveLiquidityProofWitness()
		witness.WithdrawProof = std.SetEmptyWithdrawProofWitness()
		witness.RangeProofs[0] = std.SetEmptyCtRangeProofWitness()
		witness.RangeProofs[1] = std.SetEmptyCtRangeProofWitness()
		witness.RangeProofs[2] = std.SetEmptyCtRangeProofWitness()
		break
	case TxTypeLock:
		// convert to special proof
		tx, b := oproof.(*DepositOrLockTx)
		if !b {
			log.Println("[SetTxWitness] unable to convert proof to special type")
			return witness, errors.New("[SetTxWitness] unable to convert proof to special type")
		}
		// set witness
		witness.TxType.Assign(uint64(txType))
		witness.DepositTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.LockTxInfo, err = std.SetDepositOrLockWitness(tx, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.UnlockProof = std.SetEmptyUnlockProofWitness()
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = std.SetEmptySwapProofWitness()
		witness.AddLiquidityProof = std.SetEmptyAddLiquidityProofWitness()
		witness.RemoveLiquidityProof = std.SetEmptyRemoveLiquidityProofWitness()
		witness.WithdrawProof = std.SetEmptyWithdrawProofWitness()
		witness.RangeProofs[0] = std.SetEmptyCtRangeProofWitness()
		witness.RangeProofs[1] = std.SetEmptyCtRangeProofWitness()
		witness.RangeProofs[2] = std.SetEmptyCtRangeProofWitness()
		break
	case TxTypeTransfer:
		// convert to special proof
		proof, b := oproof.(*TransferProof)
		if !b {
			log.Println("[SetTxWitness] unable to convert proof to special type")
			return witness, errors.New("[SetTxWitness] unable to convert proof to special type")
		}
		proofConstraints, err := std.SetTransferProofWitness(proof, isEnabled)
		if err != nil {
			return witness, err
		}
		// set witness
		witness.TxType.Assign(uint64(txType))
		witness.DepositTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.LockTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.UnlockProof = std.SetEmptyUnlockProofWitness()
		witness.TransferProof = proofConstraints
		for i, subProof := range proof.SubProofs {
			witness.RangeProofs[i], err = std.SetCtRangeProofWitness(subProof.BStarRangeProof, isEnabled)
			if err != nil {
				return witness, err
			}
		}
		witness.SwapProof = std.SetEmptySwapProofWitness()
		witness.AddLiquidityProof = std.SetEmptyAddLiquidityProofWitness()
		witness.RemoveLiquidityProof = std.SetEmptyRemoveLiquidityProofWitness()
		witness.WithdrawProof = std.SetEmptyWithdrawProofWitness()
		break
	case TxTypeSwap:
		proof, b := oproof.(*SwapProof)
		if !b {
			return witness, errors.New("[SetTxWitness] unable to convert proof to special type")
		}
		proofConstraints, err := std.SetSwapProofWitness(proof, isEnabled)
		if err != nil {
			return witness, err
		}
		// set witness
		witness.TxType.Assign(uint64(txType))
		witness.DepositTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.LockTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.UnlockProof = std.SetEmptyUnlockProofWitness()
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = proofConstraints
		witness.RangeProofs[0], err = std.SetCtRangeProofWitness(proof.ARangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[1], err = std.SetCtRangeProofWitness(proof.GasFeePrimeRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[2] = witness.RangeProofs[1]
		witness.AddLiquidityProof = std.SetEmptyAddLiquidityProofWitness()
		witness.RemoveLiquidityProof = std.SetEmptyRemoveLiquidityProofWitness()
		witness.WithdrawProof = std.SetEmptyWithdrawProofWitness()
		break
	case TxTypeAddLiquidity:
		proof, b := oproof.(*AddLiquidityProof)
		if !b {
			return witness, errors.New("[SetTxWitness] unable to convert proof to special type")
		}
		proofConstraints, err := std.SetAddLiquidityProofWitness(proof, isEnabled)
		if err != nil {
			return witness, err
		}
		// set witness
		witness.TxType.Assign(uint64(txType))
		witness.DepositTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.LockTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.UnlockProof = std.SetEmptyUnlockProofWitness()
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = std.SetEmptySwapProofWitness()
		witness.AddLiquidityProof = proofConstraints
		witness.RangeProofs[0], err = std.SetCtRangeProofWitness(proof.ARangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[1], err = std.SetCtRangeProofWitness(proof.BRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[2], err = std.SetCtRangeProofWitness(proof.GasFeePrimeRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RemoveLiquidityProof = std.SetEmptyRemoveLiquidityProofWitness()
		witness.WithdrawProof = std.SetEmptyWithdrawProofWitness()
		break
	case TxTypeRemoveLiquidity:
		proof, b := oproof.(*RemoveLiquidityProof)
		if !b {
			return witness, errors.New("[SetTxWitness] unable to convert proof to special type")
		}
		proofConstraints, err := std.SetRemoveLiquidityProofWitness(proof, isEnabled)
		if err != nil {
			return witness, err
		}
		// set witness
		witness.TxType.Assign(uint64(txType))
		witness.DepositTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.LockTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.UnlockProof = std.SetEmptyUnlockProofWitness()
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = std.SetEmptySwapProofWitness()
		witness.AddLiquidityProof = std.SetEmptyAddLiquidityProofWitness()
		witness.RemoveLiquidityProof = proofConstraints
		witness.RangeProofs[0], err = std.SetCtRangeProofWitness(proof.LPRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[1], err = std.SetCtRangeProofWitness(proof.GasFeePrimeRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[2] = witness.RangeProofs[0]
		witness.WithdrawProof = std.SetEmptyWithdrawProofWitness()
		break
	case TxTypeUnlock:
		proof, b := oproof.(*UnlockProof)
		if !b {
			return witness, errors.New("[SetTxWitness] unable to convert proof to special type")
		}
		proofConstraints, err := std.SetUnlockProofWitness(proof, isEnabled)
		if err != nil {
			return witness, err
		}
		// set witness
		witness.TxType.Assign(uint64(txType))
		witness.DepositTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.LockTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.UnlockProof = proofConstraints
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = std.SetEmptySwapProofWitness()
		witness.AddLiquidityProof = std.SetEmptyAddLiquidityProofWitness()
		witness.RemoveLiquidityProof = std.SetEmptyRemoveLiquidityProofWitness()
		witness.WithdrawProof = std.SetEmptyWithdrawProofWitness()
		witness.RangeProofs[0], err = std.SetCtRangeProofWitness(proof.GasFeePrimeRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[1] = witness.RangeProofs[0]
		witness.RangeProofs[2] = witness.RangeProofs[0]
		break
	case TxTypeWithdraw:
		proof, b := oproof.(*WithdrawProof)
		if !b {
			return witness, errors.New("[SetTxWitness] unable to convert proof to special type")
		}
		proofConstraints, err := std.SetWithdrawProofWitness(proof, isEnabled)
		if err != nil {
			return witness, err
		}
		// set witness
		witness.TxType.Assign(uint64(txType))
		witness.DepositTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.LockTxInfo = std.SetEmptyDepositOrLockWitness()
		witness.UnlockProof = std.SetEmptyUnlockProofWitness()
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = std.SetEmptySwapProofWitness()
		witness.AddLiquidityProof = std.SetEmptyAddLiquidityProofWitness()
		witness.RemoveLiquidityProof = std.SetEmptyRemoveLiquidityProofWitness()
		witness.WithdrawProof = proofConstraints
		witness.RangeProofs[0], err = std.SetCtRangeProofWitness(proof.BPrimeRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[1], err = std.SetCtRangeProofWitness(proof.GasFeePrimeRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[2] = witness.RangeProofs[0]
		break
	default:
		log.Println("[SetTxWitness] invalid tx type")
		return witness, errors.New("[SetTxWitness] invalid tx type")
	}
	// set common account & merkle parts
	// account root before
	witness.AccountRootBefore.Assign(oTx.AccountRootBefore)
	// account before info, size is 4
	for i := 0; i < NbAccountsPerTx; i++ {
		witness.AccountsInfoBefore[i], err = SetAccountWitness(oTx.AccountsInfoBefore[i])
		if err != nil {
			log.Println("[SetTxWitness] err info:", err)
			return witness, err
		}
	}
	// before account asset merkle proof
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			copy(
				witness.MerkleProofsAccountAssetsBefore[i][j][:],
				std.SetMerkleProofsWitness(oTx.MerkleProofsAccountAssetsBefore[i][j][:], AssetMerkleLevels))
			copy(
				witness.MerkleProofsHelperAccountAssetsBefore[i][j][:],
				std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountAssetsBefore[i][j][:], AssetMerkleHelperLevels))
			//witness.MerkleProofsAccountAssetsBefore[i][j] =
			//	std.SetMerkleProofsWitness(oTx.MerkleProofsAccountAssetsBefore[i][j][:], AssetMerkleLevels)
			//witness.MerkleProofsHelperAccountAssetsBefore[i][j] =
			//	std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountAssetsBefore[i][j][:], AssetMerkleHelperLevels)
		}
	}
	// before account asset lock merkle proof
	for i := 0; i < NbAccountsPerTx; i++ {
		copy(
			witness.MerkleProofsAccountLockedAssetsBefore[i][:],
			std.SetMerkleProofsWitness(oTx.MerkleProofsAccountLockedAssetsBefore[i][:], LockedAssetMerkleLevels))
		copy(
			witness.MerkleProofsHelperAccountLockedAssetsBefore[i][:],
			std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountLockedAssetsBefore[i][:], LockedAssetMerkleHelperLevels))
		//witness.MerkleProofsAccountLockedAssetsBefore[i] =
		//	std.SetMerkleProofsWitness(oTx.MerkleProofsAccountLockedAssetsBefore[i][:], LockedAssetMerkleLevels)
		//witness.MerkleProofsHelperAccountLockedAssetsBefore[i] =
		//	std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountLockedAssetsBefore[i][:], LockedAssetMerkleHelperLevels)
	}
	// before account liquidity merkle proof
	for i := 0; i < NbAccountsPerTx; i++ {
		copy(
			witness.MerkleProofsAccountLiquidityBefore[i][:],
			std.SetMerkleProofsWitness(oTx.MerkleProofsAccountLiquidityBefore[i][:], LiquidityMerkleLevels))
		copy(
			witness.MerkleProofsHelperAccountLiquidityBefore[i][:],
			std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountLiquidityBefore[i][:], LiquidityMerkleHelperLevels))
		//witness.MerkleProofsAccountLiquidityBefore[i] =
		//	std.SetMerkleProofsWitness(oTx.MerkleProofsAccountLiquidityBefore[i][:], LiquidityMerkleLevels)
		//witness.MerkleProofsHelperAccountLiquidityBefore[i] =
		//	std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountLiquidityBefore[i][:], LiquidityMerkleHelperLevels)
	}
	// before account merkle proof
	for i := 0; i < NbAccountsPerTx; i++ {
		copy(
			witness.MerkleProofsAccountBefore[i][:],
			std.SetMerkleProofsWitness(oTx.MerkleProofsAccountBefore[i][:], AccountMerkleLevels))
		copy(
			witness.MerkleProofsHelperAccountBefore[i][:],
			std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountBefore[i][:], AccountMerkleHelperLevels))
		//witness.MerkleProofsAccountBefore[i] =
		//	std.SetMerkleProofsWitness(oTx.MerkleProofsAccountBefore[i][:], AccountMerkleLevels)
		//witness.MerkleProofsHelperAccountBefore[i] =
		//	std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountBefore[i][:], AccountMerkleHelperLevels)
	}
	// account root after
	witness.AccountRootAfter.Assign(oTx.AccountRootAfter)
	// account after info, size is 4
	for i := 0; i < NbAccountsPerTx; i++ {
		witness.AccountsInfoAfter[i], err = SetAccountWitness(oTx.AccountsInfoAfter[i])
		if err != nil {
			log.Println("[SetTxWitness] err info:", err)
			return witness, err
		}
	}
	// after account asset merkle proof
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			copy(
				witness.MerkleProofsAccountAssetsAfter[i][j][:],
				std.SetMerkleProofsWitness(oTx.MerkleProofsAccountAssetsAfter[i][:], AssetMerkleLevels))
			copy(
				witness.MerkleProofsHelperAccountAssetsAfter[i][j][:],
				std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountAssetsAfter[i][:], AssetMerkleHelperLevels))
		}
		//witness.MerkleProofsAccountAssetsAfter[i] =
		//	std.SetMerkleProofsWitness(oTx.MerkleProofsAccountAssetsAfter[i][:], AssetMerkleLevels)
		//witness.MerkleProofsHelperAccountAssetsAfter[i] =
		//	std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountAssetsAfter[i][:], AssetMerkleHelperLevels)
	}
	// after account asset lock merkle proof
	for i := 0; i < NbAccountsPerTx; i++ {
		copy(
			witness.MerkleProofsAccountLockedAssetsAfter[i][:],
			std.SetMerkleProofsWitness(oTx.MerkleProofsAccountLockedAssetsAfter[i][:], LockedAssetMerkleLevels))
		copy(
			witness.MerkleProofsHelperAccountLockedAssetsAfter[i][:],
			std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountLockedAssetsAfter[i][:], LockedAssetMerkleHelperLevels))
		//witness.MerkleProofsAccountLockedAssetsAfter[i] =
		//	std.SetMerkleProofsWitness(oTx.MerkleProofsAccountLockedAssetsAfter[i][:], LockedAssetMerkleLevels)
		//witness.MerkleProofsHelperAccountLockedAssetsAfter[i] =
		//	std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountLockedAssetsAfter[i][:], LockedAssetMerkleHelperLevels)
	}
	// after account liquidity merkle proof
	for i := 0; i < NbAccountsPerTx; i++ {
		copy(
			witness.MerkleProofsAccountLiquidityAfter[i][:],
			std.SetMerkleProofsWitness(oTx.MerkleProofsAccountLiquidityAfter[i][:], LiquidityMerkleLevels))
		copy(
			witness.MerkleProofsHelperAccountLiquidityAfter[i][:],
			std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountLiquidityAfter[i][:], LiquidityMerkleHelperLevels))
		//witness.MerkleProofsAccountLiquidityAfter[i] =
		//	std.SetMerkleProofsWitness(oTx.MerkleProofsAccountLiquidityAfter[i][:], LiquidityMerkleLevels)
		//witness.MerkleProofsHelperAccountLiquidityAfter[i] =
		//	std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountLiquidityAfter[i][:], LiquidityMerkleHelperLevels)
	}
	// after account merkle proof
	for i := 0; i < NbAccountsPerTx; i++ {
		copy(
			witness.MerkleProofsAccountAfter[i][:],
			std.SetMerkleProofsWitness(oTx.MerkleProofsAccountAfter[i][:], AccountMerkleLevels))
		copy(
			witness.MerkleProofsHelperAccountAfter[i][:],
			std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountAfter[i][:], AccountMerkleHelperLevels))
		//witness.MerkleProofsAccountAfter[i] =
		//	std.SetMerkleProofsWitness(oTx.MerkleProofsAccountAfter[i][:], AccountMerkleLevels)
		//witness.MerkleProofsHelperAccountAfter[i] =
		//	std.SetMerkleProofsHelperWitness(oTx.MerkleProofsHelperAccountAfter[i][:], AccountMerkleHelperLevels)
	}
	return witness, nil
}
