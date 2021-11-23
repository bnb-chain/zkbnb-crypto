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
	"encoding/base64"
	"encoding/json"
	"log"
	"syscall/js"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

/*
	ProveTransfer: prove privacy transfer
	@AssetId: asset id
	@fee: fee
	@segmentInfosStr: string of segmentInfo array, which are used to generate the transfer proof
*/
func ProveTransfer() js.Func {
	proveTransferFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 4 {
			return ErrInvalidTransferParams
		}
		// read token id
		assetIdInt := args[0].Int()
		if assetIdInt < 0 {
			return ErrInvalidTransferParams
		}
		assetId := uint32(assetIdInt)
		// GasFee
		GasFeeInt := args[1].Int()
		if GasFeeInt < 0 {
			return ErrInvalidTransferParams
		}
		GasFee := uint64(GasFeeInt)
		// memo
		memo := args[2].String()
		// read segmentInfo Str
		segmentInfosStr := args[3].String()
		// parse segmentInfo: []TransferSegment
		segments, errStr := FromTransferSegmentJSON(segmentInfosStr)
		if errStr != Success {
			log.Println("[ProveTransfer] err info: ", errStr)
			return errStr
		}
		relation, err := zecrey.NewTransferProofRelation(assetId, GasFee)
		if err != nil {
			log.Println("[ProveTransfer] err info: ", err)
			return ErrInvalidTransferRelationParams
		}
		// set up accountsIndex
		accountsIndex := make([]uint32, len(segments))
		for i, segment := range segments {
			accountsIndex[i] = segment.AccountIndex
			err = relation.AddStatement(segment.BalanceEnc, segment.Pk, segment.Balance, segment.BDelta, segment.Sk)
			if err != nil {
				log.Println("[ProveTransfer] err info: ", err)
				return ErrInvalidTransferRelationParams
			}
		}
		transferProof, err := zecrey.ProveTransfer(relation)
		if err != nil {
			log.Println("[ProveTransfer] err info: ", err)
			return ErrProveTransfer
		}
		tx := &TransferTxInfo{
			// token id
			AssetId: assetId,
			// account indexes
			AccountsIndex: accountsIndex,
			// GasFee
			GasFee: GasFee,
			// transfer proof
			Proof: transferProof.String(),
			Memo:  memo,
		}
		txBytes, err := json.Marshal(tx)
		if err != nil {
			log.Println("[ProveTransfer] err info: ", ErrMarshalTx)
			return ErrMarshalTx
		}
		return base64.StdEncoding.EncodeToString(txBytes)
	})
	return proveTransferFunc
}
