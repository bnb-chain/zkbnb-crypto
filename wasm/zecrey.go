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
	"math/big"
	"syscall/js"
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
		cId := uint8(chainId)
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
			ChainId:       cId,
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
		if len(args) != 5 {
			return ErrInvalidTransferParams
		}
		chainId := args[0].Int()
		cId := uint8(chainId)
		// read token id
		assetId := args[1].Int()
		if assetId < 0 {
			return ErrInvalidTransferParams
		}
		tId := uint32(assetId)
		// fee
		feeInt := args[2].Int()
		if feeInt < 0 {
			return ErrInvalidTransferParams
		}
		fee := uint32(feeInt)
		// read accounts indexes str
		accountsIndexStr := args[3].String()
		// read segmentInfo Str
		segmentInfosStr := args[4].String()

		var accountsIndex []uint32
		err := json.Unmarshal([]byte(accountsIndexStr), &accountsIndex)
		if err != nil {
			return ErrInvalidTransferParams
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
			ChainId: cId,
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
		if len(args) != 8 {
			return ErrInvalidSwapParams
		}
		chainIdFrom := args[0].Int()
		cIdFrom := uint8(chainIdFrom)
		chainIdTo := args[1].Int()
		cIdTo := uint8(chainIdTo)
		// read fromAssetId
		fromAssetId := args[2].Int()
		if fromAssetId < 0 {
			return ErrInvalidSwapParams
		}
		// transfer fromAssetId to uint32
		assetIdFrom := uint32(fromAssetId)
		// read toAssetId
		toAssetId := args[3].Int()
		if toAssetId < 0 {
			return ErrInvalidSwapParams
		}
		// transfer fromAssetId to uint32
		assetIdTo := uint32(toAssetId)
		// fee
		feeInt := args[4].Int()
		if feeInt < 0 {
			return ErrInvalidSwapParams
		}
		fee := uint32(feeInt)
		// account index
		accountIndexFrom := args[5].Int()
		accountIndexTo := args[6].Int()
		// read segmentInfo JSON str
		segmentInfo := args[7].String()
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
			ChainIdFrom:      cIdFrom,
			ChainIdTo:        cIdTo,
			AssetIdFrom:      assetIdFrom,
			AssetIdTo:        assetIdTo,
			AccountIndexFrom: uint32(accountIndexFrom),
			AccountIndexTo:   uint32(accountIndexTo),
			Fee:              fee,
			BStarFrom:        segment.BStarFrom,
			BStarTo:          segment.BStarTo,
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
