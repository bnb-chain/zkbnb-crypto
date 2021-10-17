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
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/zecrey/circuit/bn254/std"
)

type TxConstraints struct {
	// tx type
	TxType Variable
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
	// range proofs
	RangeProofs [MaxRangeProofCount]CtRangeProofConstraints
}

func (circuit TxConstraints) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	// mimc
	hFunc, err := mimc.NewMiMC(zmimc.SEED, curveID, cs)
	if err != nil {
		return err
	}

	// TODO verify H: need to optimize
	H := Point{
		X: cs.Constant(std.HX),
		Y: cs.Constant(std.HY),
	}
	circuit.TransferProof.H = H
	circuit.SwapProof.H = H
	circuit.AddLiquidityProof.H = H
	circuit.RemoveLiquidityProof.H = H
	circuit.WithdrawProof.H = H
	VerifyTransaction(cs, circuit, params, hFunc)

	return nil
}

func VerifyTransaction(
	cs *ConstraintSystem,
	tx TxConstraints,
	params twistededwards.EdCurve,
	hFunc MiMC,
) {
	// txType constants
	txTypeTransfer := cs.Constant(uint64(TxTypeTransfer))
	txTypeSwap := cs.Constant(uint64(TxTypeSwap))
	txTypeAddLiquidity := cs.Constant(uint64(TxTypeAddLiquidity))
	txTypeRemoveLiquidity := cs.Constant(uint64(TxTypeRemoveLiquidity))
	txTypeWithdraw := cs.Constant(uint64(TxTypeWithdraw))
	tx.TransferProof.IsEnabled = cs.IsZero(cs.Sub(tx.TxType, txTypeTransfer))
	tx.SwapProof.IsEnabled = cs.IsZero(cs.Sub(tx.TxType, txTypeSwap))
	tx.AddLiquidityProof.IsEnabled = cs.IsZero(cs.Sub(tx.TxType, txTypeAddLiquidity))
	tx.RemoveLiquidityProof.IsEnabled = cs.IsZero(cs.Sub(tx.TxType, txTypeRemoveLiquidity))
	tx.WithdrawProof.IsEnabled = cs.IsZero(cs.Sub(tx.TxType, txTypeWithdraw))

	// verify range proofs
	for i, rangeProof := range tx.RangeProofs {
		// set range proof is true
		rangeProof.IsEnabled = cs.Constant(1)
		std.VerifyCtRangeProof(cs, rangeProof, params, hFunc)
		hFunc.Reset()
		tx.TransferProof.SubProofs[i].Y = rangeProof.A
	}
	// set T or Y
	// swap proof
	tx.SwapProof.T_uA = tx.RangeProofs[0].A
	tx.SwapProof.T_ufee = tx.RangeProofs[1].A
	// add liquidity proof
	tx.AddLiquidityProof.T_uA = tx.RangeProofs[0].A
	tx.AddLiquidityProof.T_uB = tx.RangeProofs[1].A
	// remove liquidity proof
	tx.RemoveLiquidityProof.T_uLP = tx.RangeProofs[0].A
	// withdraw proof
	tx.WithdrawProof.T = tx.RangeProofs[0].A

	// verify transfer proof
	std.VerifyTransferProof(cs, tx.TransferProof, params, hFunc)
	hFunc.Reset()
	// verify swap proof
	std.VerifySwapProof(cs, tx.SwapProof, params, hFunc)
	hFunc.Reset()
	// verify add liquidity proof
	std.VerifyAddLiquidityProof(cs, tx.AddLiquidityProof, params, hFunc)
	hFunc.Reset()
	// verify remove liquidity proof
	std.VerifyRemoveLiquidityProof(cs, tx.RemoveLiquidityProof, params, hFunc)
	hFunc.Reset()
	// verify withdraw proof
	std.VerifyWithdrawProof(cs, tx.WithdrawProof, params, hFunc)
	hFunc.Reset()

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
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = proofConstraints
		witness.RangeProofs[0], err = std.SetCtRangeProofWitness(proof.ARangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[1], err = std.SetCtRangeProofWitness(proof.FeeRangeProof, isEnabled)
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
		witness.RangeProofs[2] = witness.RangeProofs[1]
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
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = std.SetEmptySwapProofWitness()
		witness.AddLiquidityProof = std.SetEmptyAddLiquidityProofWitness()
		witness.RemoveLiquidityProof = proofConstraints
		witness.RangeProofs[0], err = std.SetCtRangeProofWitness(proof.LPRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[1] = witness.RangeProofs[0]
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
		witness.TransferProof = std.SetEmptyTransferProofWitness()
		witness.SwapProof = std.SetEmptySwapProofWitness()
		witness.AddLiquidityProof = std.SetEmptyAddLiquidityProofWitness()
		witness.RemoveLiquidityProof = std.SetEmptyRemoveLiquidityProofWitness()
		witness.WithdrawProof = proofConstraints
		witness.RangeProofs[0], err = std.SetCtRangeProofWitness(proof.BPrimeRangeProof, isEnabled)
		if err != nil {
			return witness, err
		}
		witness.RangeProofs[1] = witness.RangeProofs[0]
		witness.RangeProofs[2] = witness.RangeProofs[0]
		break
	default:
		return witness, errors.New("[SetTxWitness] invalid tx type")
	}
	return witness, nil
}
