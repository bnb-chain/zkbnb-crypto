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

package zecrey_zero

import (
	"encoding/base64"
	"encoding/json"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"syscall/js"
)

/*
	ProveSwap: helper function for the frontend for building swap tx
	@segmentInfo: segmentInfo JSON string
*/
func ProveSwap() js.Func {
	proveSwapFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 8
		if len(args) != 1 {
			return ErrInvalidSwapParams
		}
		// read segmentInfo JSON str
		segmentInfo := args[0].String()
		// parse segmentInfo
		segment, errStr := FromSwapSegmentJSON(segmentInfo)
		if errStr != Success {
			return errStr
		}
		// create withdraw relation
		relation, err := zecrey.NewSwapRelation(
			segment.C_uA,
			segment.Pk_u, segment.Pk_treasury,
			segment.AssetAId, segment.AssetBId,
			segment.B_A_Delta, segment.B_u_A,
			segment.MinB_B_Delta,
			segment.FeeRate, segment.TreasuryRate,
			segment.Sk_u,
			segment.C_fee, segment.B_fee, segment.GasFeeAssetId, segment.GasFee,
		)
		if err != nil {
			return ErrInvalidSwapRelationParams
		}
		// create withdraw proof
		proof, err := zecrey.ProveSwap(relation)
		if err != nil {
			return ErrProveSwap
		}
		swapTx := &SwapTxInfo{
			PairIndex:     segment.PairIndex,
			AccountIndex:  segment.AccountIndex,
			AssetAId:      segment.AssetAId,
			AssetBId:      segment.AssetBId,
			GasFeeAssetId: segment.GasFeeAssetId,
			GasFee:        segment.GasFee,
			FeeRate:       segment.FeeRate,
			TreasuryRate:  segment.TreasuryRate,
			B_A_Delta:     segment.B_A_Delta,
			MinB_B_Delta:  segment.MinB_B_Delta,
			Proof:         proof.String(),
		}
		txBytes, err := json.Marshal(swapTx)
		if err != nil {
			return ErrMarshalTx
		}
		return base64.StdEncoding.EncodeToString(txBytes)
	})
	return proveSwapFunc
}
