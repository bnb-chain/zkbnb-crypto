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

package wasm

import (
	"encoding/json"
	"errors"
	"math/big"
	"syscall/js"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

/*
	ProveWithdraw: helper function for the frontend for building withdraw tx
	@chainId: chain id
	@assetId: token id
	@zecreyAddr: transactions address
	@l1Addr: layer 1 address
	@segmentInfo: segmentInfo JSON string
*/
func ProveWithdraw() js.Func {
	proveWithdrawFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 3
		if len(args) != 6 {
			return ErrInvalidWithdrawParams
		}
		chainId := args[0].Int()
		if chainId < 0 {
			return ErrInvalidWithdrawParams
		}
		// read assetId
		assetId := args[1].Int()
		if assetId < 0 {
			return ErrInvalidWithdrawParams
		}
		// transfer assetId to uint32
		tId := uint32(assetId)
		// fee
		feeInt := args[2].Int()
		fee := uint32(feeInt)
		// layer 2 address
		accountIndex := args[3].Int()
		// layer 1 address
		l1addr := args[4].String()
		// read segmentInfo JSON str
		segmentInfo := args[5].String()
		// parse segmentInfo
		segment, errStr := FromWithdrawSegmentJSON(segmentInfo)
		if errStr != Success {
			return errStr
		}
		// create withdraw relation
		relation, err := zecrey.NewWithdrawRelation(segment.EncBalance, segment.Pk, segment.Balance, segment.BStar, segment.Sk, tId, l1addr, big.NewInt(int64(fee)))
		if err != nil {
			return ErrInvalidWithdrawRelationParams
		}
		// create withdraw proof
		withdrawProof, err := zecrey.ProveWithdraw(relation)
		if err != nil {
			return ErrProveWithdraw
		}
		withdrawTx := &WithdrawTxInfo{
			ChainId:       uint8(chainId),
			AssetId:       tId,
			AccountIndex:  uint32(accountIndex),
			NativeAddress: l1addr,
			Amount:        uint32(segment.BStar.Uint64()),
			Fee:           fee,
			Proof:         withdrawProof.String(),
		}
		txBytes, err := json.Marshal(withdrawTx)
		if err != nil {
			return ErrMarshalTx
		}
		return string(txBytes)
	})
	return proveWithdrawFunc
}

/*
	ProveTransfer: prove privacy transfer
	@chainId: chain id
	@assetId: token id
	@fee: fee
	@accountsIndexStr: string of int array represents account indexes
	@segmentInfosStr: string of segmentInfo array, which are used to generate the transfer proof
*/
func ProveTransfer() js.Func {
	proveTransferFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 4 {
			return ErrInvalidTransferParams
		}
		// read token id
		assetId := args[0].Int()
		if assetId < 0 {
			return ErrInvalidTransferParams
		}
		tId := uint32(assetId)
		// fee
		feeInt := args[1].Int()
		if feeInt < 0 {
			return ErrInvalidTransferParams
		}
		fee := uint32(feeInt)
		// read accounts indexes str
		accountsIndexStr := args[2].String()
		// read segmentInfo Str
		segmentInfosStr := args[3].String()

		var accountsIndex []uint32
		err := json.Unmarshal([]byte(accountsIndexStr), &accountsIndex)
		if err != nil {
			return ErrInvalidTransferParams
		}
		// TODO will be deleted
		if len(accountsIndex) != 3 {
			return errors.New("err: invalid account size, should be 3").Error()
		}
		// parse segmentInfo: []PTransferSegment
		segments, errStr := FromPTransferSegmentJSON(segmentInfosStr)
		if errStr != Success {
			return errStr
		}
		relation, err := zecrey.NewPTransferProofRelation(tId, big.NewInt(int64(fee)))
		if err != nil {
			return ErrInvalidTransferRelationParams
		}
		for _, segment := range segments {
			err := relation.AddStatement(segment.EncBalance, segment.Pk, segment.Balance, segment.BDelta, segment.Sk)
			if err != nil {
				return ErrInvalidTransferRelationParams
			}
		}
		transferProof, err := zecrey.ProvePTransfer(relation)
		if err != nil {
			return ErrProveTransfer
		}
		tx := &TransferTxInfo{
			// token id
			AssetId: tId,
			// account indexes
			AccountsIndex: accountsIndex,
			// fee
			Fee: fee,
			// transfer proof
			Proof: transferProof.String(),
		}
		txBytes, err := json.Marshal(tx)
		if err != nil {
			return ErrMarshalTx
		}
		return string(txBytes)
	})
	return proveTransferFunc
}

/*
	ProveSwap: helper function for the frontend for building swap tx
	@chainIdFrom: swap from which chain
	@chainIdTo: swap to which chain
	@fromAssetId: from token id
	@toAssetId: to token id
	@fee: fee
	@zecreyAddr: transactions address
	@segmentInfo: segmentInfo JSON string
*/
func ProveSwap() js.Func {
	proveSwapFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 8
		if len(args) != 7 {
			return ErrInvalidSwapParams
		}
		pIndex := args[0].Int()
		if pIndex < 0 {
			return ErrInvalidSwapParams
		}
		pairIndex := uint32(pIndex)
		// read fromAssetId
		fromAssetId := args[1].Int()
		if fromAssetId < 0 {
			return ErrInvalidSwapParams
		}
		// transfer fromAssetId to uint32
		assetIdFrom := uint32(fromAssetId)
		// read toAssetId
		toAssetId := args[2].Int()
		if toAssetId < 0 {
			return ErrInvalidSwapParams
		}
		// transfer fromAssetId to uint32
		assetIdTo := uint32(toAssetId)
		// fee
		feeInt := args[3].Int()
		if feeInt < 0 {
			return ErrInvalidSwapParams
		}
		fee := uint32(feeInt)
		// account index
		accountIndexFrom := args[4].Int()
		accountIndexTo := args[5].Int()
		// read segmentInfo JSON str
		segmentInfo := args[6].String()
		// parse segmentInfo
		segment, errStr := FromSwapSegmentJSON(segmentInfo)
		if errStr != Success {
			return errStr
		}
		// create withdraw relation
		relation, err := zecrey.NewSwapRelationPart1(segment.EncBalance, segment.ReceiverEncBalance, segment.Pk, segment.ReceiverPk, segment.Balance, segment.BStarFrom, segment.BStarTo, segment.Sk, assetIdFrom, assetIdTo, big.NewInt(int64(fee)))
		if err != nil {
			return ErrInvalidSwapRelationParams
		}
		// create withdraw proof
		swapProofPart1, err := zecrey.ProveSwapPart1(relation, true)
		if err != nil {
			return ErrProveWithdraw
		}
		swapTx := &SwapTxInfo{
			// pair index
			PairIndex: pairIndex,
			AssetAId:  assetIdFrom,
			AssetBId:  assetIdTo,
			// account index
			AccountIndexFrom: uint32(accountIndexFrom),
			AccountIndexTo:   uint32(accountIndexTo),
			Fee:              fee,
			DeltaX:           segment.BStarFrom,
			DeltaY:           segment.BStarTo,
			Proof:            swapProofPart1.String(),
		}
		txBytes, err := json.Marshal(swapTx)
		if err != nil {
			return ErrMarshalTx
		}
		return string(txBytes)
	})
	return proveSwapFunc
}

/*
	ProveL1PrivacyTransfer: prove l1 privacy transfer
	@depositInfo: deposit segment info
	@chainId: chain id
	@assetId: token id
	@fee: fee
	@accountsIndexStr: string of int array represents account indexes
	@segmentInfosStr: string of segmentInfo array, which are used to generate the transfer proof
*/
func ProveL1PrivacyTransfer() js.Func {
	proveTransferFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 9 {
			return ErrInvalidL1TransferParams
		}
		withdrawTo := args[0].String()
		aIndex := args[1].Int()
		if aIndex < 0 {
			return ErrInvalidL1TransferParams
		}
		accountIndex := uint32(aIndex)
		// deposit amount
		depositAmountInt := args[2].Int()
		depositAmount := uint32(depositAmountInt)
		// deposit tx hash
		depositTxHash := args[3].String()
		// chain id
		chainId := args[4].Int()
		cId := uint8(chainId)
		// asset id
		assetId := args[5].Int()
		if assetId < 0 {
			return ErrInvalidTransferParams
		}
		aId := uint32(assetId)
		// fee
		// TODO check fee is right
		feeInt := args[6].Int()
		if feeInt < 0 {
			return ErrInvalidTransferParams
		}
		fee := uint32(feeInt)
		// read accounts indexes str
		accountsIndexStr := args[7].String()
		// read segmentInfo Str
		segmentInfosStr := args[8].String()
		//check deposit amount
		// construct deposit signed transferTxInfo
		// TODO need to optimize
		amountAndFee := big.NewInt(int64(depositAmount + fee))
		var accountsIndex []uint32
		err := json.Unmarshal([]byte(accountsIndexStr), &accountsIndex)
		if err != nil {
			return ErrInvalidTransferParams
		}
		// parse segmentInfo: []PTransferSegment
		segments, errStr := FromL1PTransferSegmentJSON(segmentInfosStr, amountAndFee)
		if errStr != Success {
			return errStr
		}
		relation, err := zecrey.NewPTransferProofRelation(aId, big.NewInt(int64(fee)))
		if err != nil {
			return ErrInvalidTransferRelationParams
		}
		for _, segment := range segments {
			err := relation.AddStatement(segment.EncBalance, segment.Pk, segment.Balance, segment.BDelta, segment.Sk)
			if err != nil {
				return err.Error()
			}
		}
		transferProof, err := zecrey.ProvePTransfer(relation)
		if err != nil {
			return err.Error()
		}
		transferTxInfo := &TransferTxInfo{
			// token id
			AssetId: aId,
			// account indexes
			AccountsIndex: accountsIndex,
			// fee
			Fee: fee,
			// transfer proof
			Proof: transferProof.String(),
		}
		l1TxInfo := &L1PrivacyTransferTxInfo{
			ChainId:       cId,
			AssetId:       aId,
			Fee:           fee,
			DepositAmount: depositAmount,
			DepositTxHash: depositTxHash,
			AccountIndex:  accountIndex,
			TransferTx:    transferTxInfo,
			WithdrawTo:    withdrawTo,
		}
		txBytes, err := json.Marshal(l1TxInfo)
		if err != nil {
			return err.Error()
		}
		return string(txBytes)
	})
	return proveTransferFunc
}

/*
	ProveAddLiquidity: add liquidity
	TODO need to rewrite
*/
func ProveAddLiquidity() js.Func {
	proveAddLiquidityFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 8
		if len(args) != 9 {
			return ErrInvalidAddLiquidityParams
		}
		// account index
		aIndex := args[0].Int()
		accountIndex := uint32(aIndex)
		// pair index
		pIndex := args[1].Int()
		pairIndex := uint32(pIndex)
		// delta x
		dX := args[2].Int()
		deltaX := uint32(dX)
		// delta y
		dY := args[3].Int()
		deltaY := uint32(dY)
		// sk
		skStr := args[4].String()
		sk, b := new(big.Int).SetString(skStr, 10)
		if !b {
			return ErrParseBigInt
		}
		// asset a balance enc
		assetABalanceEnc := args[5].String()
		// asset a balance
		assetABalance := args[6].Int()
		// check balance is correct
		assetARawBalanceEnc, err := twistedElgamal.FromString(assetABalanceEnc)
		if err != nil {
			return ErrInvalidDecParams
		}
		amount, err := twistedElgamal.DecByStart(assetARawBalanceEnc, sk, int64(assetABalance), int64(assetABalance)+1)
		if err != nil {
			return ErrInvalidDecParams
		}
		if amount.Int64() != int64(assetABalance) {
			return ErrInvalidDecParams
		}
		// asset b balance enc
		assetBBalanceEnc := args[7].String()
		// asset b balance
		assetBBalance := args[8].Int()
		// check balance is correct
		assetBRawBalanceEnc, err := twistedElgamal.FromString(assetBBalanceEnc)
		if err != nil {
			return ErrInvalidDecParams
		}
		amount, err = twistedElgamal.DecByStart(assetBRawBalanceEnc, sk, int64(assetBBalance), int64(assetBBalance)+1)
		if err != nil {
			return ErrInvalidDecParams
		}
		if amount.Int64() != int64(assetBBalance) {
			return ErrInvalidDecParams
		}
		if dX > assetABalance {
			return ErrInvalidAddLiquidityParams
		}
		if dY > assetBBalance {
			return ErrInvalidAddLiquidityParams
		}
		addLiquidityTx := &AddLiquidityTxAo{
			AccountIndex: accountIndex,
			PairIndex:    pairIndex,
			DeltaX:       deltaX,
			DeltaY:       deltaY,
			BalanceEncX:  assetABalanceEnc,
			BalanceEncY:  assetBBalanceEnc,
		}
		txBytes, err := json.Marshal(addLiquidityTx)
		if err != nil {
			return ErrMarshalTx
		}
		return string(txBytes)
	})
	return proveAddLiquidityFunc
}

/*
	ProveRemoveLiquidity: remove liquidity
	TODO need to rewrite
*/
func ProveRemoveLiquidity() js.Func {
	proveRemoveLiquidityFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 8
		if len(args) != 6 {
			return ErrInvalidRemoveLiquidityParams
		}
		// account index
		aIndex := args[0].Int()
		accountIndex := uint32(aIndex)
		// pair index
		pIndex := args[1].Int()
		pairIndex := uint32(pIndex)
		// sk
		skStr := args[2].String()
		sk, b := new(big.Int).SetString(skStr, 10)
		if !b {
			return ErrParseBigInt
		}
		// lp balance enc
		// asset lp balance enc
		lpEnc := args[3].String()
		totalLpAmount := args[4].Int()
		lpAmount := args[5].Int()
		// check balance is correct
		lpRawEnc, err := twistedElgamal.FromString(lpEnc)
		if err != nil {
			return ErrInvalidDecParams
		}
		amount, err := twistedElgamal.DecByStart(lpRawEnc, sk, int64(totalLpAmount), int64(totalLpAmount)+1)
		if err != nil {
			return ErrInvalidDecParams
		}
		if amount.Int64() != int64(totalLpAmount) {
			return ErrInvalidDecParams
		}
		removeLiquidityTx := &RemoveLiquidityTxAo{
			AccountIndex: accountIndex,
			PairIndex:    pairIndex,
			LpAmount:     uint32(lpAmount),
			LpEnc:        lpEnc,
		}
		txBytes, err := json.Marshal(removeLiquidityTx)
		if err != nil {
			return ErrMarshalTx
		}
		return string(txBytes)
	})
	return proveRemoveLiquidityFunc
}
