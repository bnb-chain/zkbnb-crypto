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
	"syscall/js"
	"time"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

/*
	ProveWithdraw: helper function for the frontend for building withdraw tx
	@tokenId: token id
	@zecreyAddr: transactions address
	@l1Addr: layer 1 address
	@segmentInfo: segmentInfo JSON string
*/
func ProveWithdraw() js.Func {
	proveWithdrawFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 3
		if len(args) != 4 {
			return ErrInvalidWithdrawParams
		}
		// read tokenId
		tokenId := args[0].Int()
		if tokenId <= 0 {
			return ErrInvalidWithdrawParams
		}
		// transfer tokenId to uint32
		tId := uint32(tokenId)
		// layer 2 address
		l2addr := args[1].String()
		// layer 1 address
		l1addr := args[2].String()
		// read segmentInfo JSON str
		segmentInfo := args[3].String()
		// parse segmentInfo
		segment, errStr := FromWithdrawSegmentJSON(segmentInfo)
		if errStr != Success {
			return errStr
		}
		// create withdraw relation
		relation, err := zecrey.NewWithdrawRelation(segment.EncVal, segment.Pk, segment.BStar, segment.Sk, tId, l1addr)
		if err != nil {
			return ErrInvalidWithdrawRelationParams
		}
		// create withdraw proof
		withdrawProof, err := zecrey.ProveWithdraw(relation)
		if err != nil {
			return ErrProveWithdraw
		}
		withdrawTx := &WithdrawTransactionAo{
			TokenId:   tId,
			L2Address: l2addr,
			L1Address: l1addr,
			Proof:     withdrawProof,
			CreateAt:  time.Now().Unix(),
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
	@tokenId: token id
	@zecreyAddrsStr: string of int array represents account indexes
	@segmentInfosStr: string of segmentInfo array, which are used to generate the transfer proof
*/
func ProveTransfer() js.Func {
	proveTransferFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 3 {
			return ErrInvalidTransferParams
		}
		// read token id
		tokenId := args[0].Int()
		if tokenId <= 0 {
			return ErrInvalidTransferParams
		}
		tId := uint32(tokenId)
		// read addressesStr Str
		addressesStr := args[1].String()
		// read segmentInfo Str
		segmentInfosStr := args[2].String()

		// parse accountIds: []int
		var addresses []string
		err := json.Unmarshal([]byte(addressesStr), &addresses)
		if err != nil {
			return ErrInvalidTransferParams
		}
		// parse segmentInfo: []PTransferSegment
		segments, errStr := FromPTransferSegmentJSON(segmentInfosStr)
		if errStr != Success {
			return errStr
		}
		relation, err := zecrey.NewPTransferProofRelation(tId)
		if err != nil {
			return ErrInvalidTransferRelationParams
		}
		for _, segment := range segments {
			err := relation.AddStatement(segment.EncVal, segment.Pk, segment.BDelta, segment.Sk)
			if err != nil {
				return ErrInvalidTransferRelationParams
			}
		}
		transferProof, err := zecrey.ProvePTransfer(relation)
		if err != nil {
			return ErrProveTransfer
		}
		tx := &TransferTransactionAo{
			// token id
			TokenId: tId,
			// account indexes
			Addresses: addresses,
			// transfer proof
			Proof: transferProof,
			// create time
			CreateAt: time.Now().Unix(),
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
	@fromTokenId: from token id
	@toTokenId: to token id
	@zecreyAddr: transactions address
	@segmentInfo: segmentInfo JSON string
*/
func ProveSwap() js.Func {
	proveSwapFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 3
		if len(args) != 4 {
			return ErrInvalidSwapParams
		}
		// read fromTokenId
		fromTokenId := args[0].Int()
		if fromTokenId <= 0 {
			return ErrInvalidSwapParams
		}
		// transfer fromTokenId to uint32
		tIdFrom := uint32(fromTokenId)
		// read toTokenId
		toTokenId := args[1].Int()
		if toTokenId <= 0 {
			return ErrInvalidSwapParams
		}
		// transfer fromTokenId to uint32
		tIdTo := uint32(toTokenId)
		// layer 2 address
		l2addr := args[2].String()
		// read segmentInfo JSON str
		segmentInfo := args[3].String()
		// parse segmentInfo
		segment, errStr := FromSwapSegmentJSON(segmentInfo)
		if errStr != Success {
			return errStr
		}
		// create withdraw relation
		relation, err := zecrey.NewSwapRelationPart1(segment.EncVal, segment.Pk, segment.BStarFrom, segment.BStarTo, segment.Sk, tIdFrom, tIdTo)
		if err != nil {
			return ErrInvalidSwapRelationParams
		}
		// create withdraw proof
		swapProofPart1, err := zecrey.ProveSwapPart1(relation, true)
		if err != nil {
			return ErrProveWithdraw
		}
		swapTx := &SwapTransactionAo{
			TokenIdFrom: tIdFrom,
			TokenIdTo:   tIdTo,
			L2Address:   l2addr,
			BStarFrom:   segment.BStarFrom,
			BStarTo:     segment.BStarTo,
			Proof:       swapProofPart1,
			CreateAt:    time.Now().Unix(),
		}
		txBytes, err := json.Marshal(swapTx)
		if err != nil {
			return ErrMarshalTx
		}
		return string(txBytes)
	})
	return proveSwapFunc
}
