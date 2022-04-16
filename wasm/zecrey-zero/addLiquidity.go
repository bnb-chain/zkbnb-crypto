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
	"log"
	"syscall/js"
)

/*
	ProveAddLiquidity: add liquidity
	@segmentInfo: string JSON format
*/
func ProveAddLiquidity() js.Func {
	proveAddLiquidityFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 1
		if len(args) != 1 {
			return ErrInvalidAddLiquidityParams
		}
		// segment info
		segmentInfo := args[0].String()
		// parse segmentInfo
		segment, errStr := FromAddLiquiditySegmentJSON(segmentInfo)
		if errStr != Success {
			return errStr
		}
		// check Balance is correct
		relation, err := zecrey.NewAddLiquidityRelation(
			segment.C_uA, segment.C_uB,
			segment.Pk_pool, segment.Pk_u,
			segment.AssetAId, segment.AssetBId,
			segment.B_uA, segment.B_uB,
			segment.B_A_Delta, segment.B_B_Delta,
			segment.Sk_u,
			segment.C_fee, segment.B_fee, segment.GasFeeAssetId, segment.GasFee,
		)
		if err != nil {
			log.Println("[ProveAddLiquidity] err info:", err)
			return err.Error()
		}
		proof, err := zecrey.ProveAddLiquidity(relation)
		if err != nil {
			log.Println("[ProveAddLiquidity] err info:", err)
			return err.Error()
		}
		addLiquidityTx := &AddLiquidityTxInfo{
			PairIndex:     segment.PairIndex,
			AccountIndex:  segment.AccountIndex,
			AssetAId:      segment.AssetAId,
			AssetBId:      segment.AssetBId,
			B_A_Delta:     segment.B_A_Delta,
			B_B_Delta:     segment.B_B_Delta,
			GasFeeAssetId: segment.GasFeeAssetId,
			GasFee:        segment.GasFee,
			Proof:         proof.String(),
		}
		txBytes, err := json.Marshal(addLiquidityTx)
		if err != nil {
			log.Println("[ProveAddLiquidity] err info:", err)
			return ErrMarshalTx
		}
		return base64.StdEncoding.EncodeToString(txBytes)
	})
	return proveAddLiquidityFunc
}
