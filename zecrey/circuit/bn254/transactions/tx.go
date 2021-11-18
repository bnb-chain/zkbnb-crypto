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
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/zecrey/circuit/bn254/std"
)

type TxConstraints struct {
	// tx type
	TxType Variable
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

	// TODO verify H: need to optimize
	H := Point{
		X: api.Constant(std.HX),
		Y: api.Constant(std.HY),
	}
	tool := std.NewEccTool(api, params)
	VerifyTransaction(tool, api, circuit, hFunc, H)

	return nil
}

func VerifyTransaction(
	tool *std.EccTool,
	api API,
	tx TxConstraints,
	hFunc MiMC,
	h Point,
) {
	// txType constants
	txTypeUnlock := api.Constant(uint64(TxTypeUnlock))
	txTypeTransfer := api.Constant(uint64(TxTypeTransfer))
	txTypeSwap := api.Constant(uint64(TxTypeSwap))
	txTypeAddLiquidity := api.Constant(uint64(TxTypeAddLiquidity))
	txTypeRemoveLiquidity := api.Constant(uint64(TxTypeRemoveLiquidity))
	txTypeWithdraw := api.Constant(uint64(TxTypeWithdraw))
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

	// verify range proofs
	for i, rangeProof := range tx.RangeProofs {
		// set range proof is true
		rangeProof.IsEnabled = api.Constant(1)
		std.VerifyCtRangeProof(tool, api, rangeProof, hFunc)
		hFunc.Reset()
		tx.TransferProof.SubProofs[i].Y = rangeProof.A
	}
	// set T or Y
	// unlock proof
	tx.UnlockProof.T_fee = tx.RangeProofs[0].A
	// swap proof
	tx.SwapProof.T_uA = tx.RangeProofs[0].A
	tx.SwapProof.T_fee = tx.RangeProofs[1].A
	// add liquidity proof
	tx.AddLiquidityProof.T_uA = tx.RangeProofs[0].A
	tx.AddLiquidityProof.T_uB = tx.RangeProofs[1].A
	// remove liquidity proof
	tx.RemoveLiquidityProof.T_uLP = tx.RangeProofs[0].A
	// withdraw proof
	tx.WithdrawProof.T = tx.RangeProofs[0].A
	// verify unlock proof
	var (
		c, cCheck               Variable
		pkProofs, pkProofsCheck [MaxRangeProofCount]std.CommonPkProof
		tProofs, tProofsCheck   [MaxRangeProofCount]std.CommonTProof
	)
	c, pkProofs, tProofs = std.VerifyUnlockProof(tool, api, tx.UnlockProof, hFunc, h)
	hFunc.Reset()
	// verify transfer proof
	cCheck, pkProofsCheck, tProofsCheck = std.VerifyTransferProof(tool, api, tx.TransferProof, hFunc, h)
	hFunc.Reset()
	c, pkProofs, tProofs = SelectCommonPart(api, isTransferTx, cCheck, c, pkProofsCheck, pkProofs, tProofsCheck, tProofs)
	// verify swap proof
	cCheck, pkProofsCheck, tProofsCheck = std.VerifySwapProof(tool, api, tx.SwapProof, hFunc, h)
	hFunc.Reset()
	c, pkProofs, tProofs = SelectCommonPart(api, isSwapTx, cCheck, c, pkProofsCheck, pkProofs, tProofsCheck, tProofs)
	// verify add liquidity proof
	cCheck, pkProofsCheck, tProofsCheck = std.VerifyAddLiquidityProof(tool, api, tx.AddLiquidityProof, hFunc, h)
	hFunc.Reset()
	c, pkProofs, tProofs = SelectCommonPart(api, isAddLiquidityTx, cCheck, c, pkProofsCheck, pkProofs, tProofsCheck, tProofs)
	// verify remove liquidity proof
	cCheck, pkProofsCheck, tProofsCheck = std.VerifyRemoveLiquidityProof(tool, api, tx.RemoveLiquidityProof, hFunc, h)
	hFunc.Reset()
	c, pkProofs, tProofs = SelectCommonPart(api, isRemoveLiquidityTx, cCheck, c, pkProofsCheck, pkProofs, tProofsCheck, tProofs)
	// verify withdraw proof
	cCheck, pkProofsCheck, tProofsCheck = std.VerifyWithdrawProof(tool, api, tx.WithdrawProof, hFunc, h)
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

}

func SetTxWitness(oproof interface{}, txType uint8, isEnabled bool) (witness TxConstraints, err error) {
	switch txType {
	case TxTypeNoop:
		break
	case TxTypeDeposit:
		break
	case TxTypeLock:
		break
	case TxTypeTransfer:
		proof, b := oproof.(*TransferProof)
		if !b {
			return witness, errors.New("[SetTxWitness] unable to convert proof to special type")
		}
		proofConstraints, err := std.SetTransferProofWitness(proof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.TxType.Assign(uint64(txType))
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
		witness.TxType.Assign(uint64(txType))
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
		witness.TxType.Assign(uint64(txType))
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
		witness.TxType.Assign(uint64(txType))
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
		witness.TxType.Assign(uint64(txType))
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
		return witness, errors.New("[SetTxWitness] invalid tx type")
	}
	return witness, nil
}
