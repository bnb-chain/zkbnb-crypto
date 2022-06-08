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

package src

import (
	"encoding/base64"
	"encoding/json"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"log"
	"syscall/js"
)

/*
	ProveRemoveLiquidity: remove liquidity
	@segmentInfo: string JSON format
*/
func ProveRemoveLiquidity() js.Func {
	proveRemoveLiquidityFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 1
		if len(args) != 1 {
			return ErrInvalidRemoveLiquidityParams
		}
		// account index
		segmentInfo := args[0].String()
		// parse segmentInfo
		segment, errStr := FromRemoveLiquiditySegmentJSON(segmentInfo)
		if errStr != Success {
			return errStr
		}
		// check Balance is correct
		relation, err := zecrey.NewRemoveLiquidityRelation(
			segment.C_u_LP,
			segment.Pk_u,
			segment.B_LP,
			segment.Delta_LP,
			segment.MinB_A_Delta, segment.MinB_B_Delta,
			segment.AssetAId, segment.AssetBId,
			segment.Sk_u,
			segment.C_fee, segment.B_fee, segment.GasFeeAssetId, segment.GasFee,
		)
		if err != nil {
			log.Println("[ProveRemoveLiquidity] err info:", err)
			return err.Error()
		}
		proof, err := zecrey.ProveRemoveLiquidity(relation)
		if err != nil {
			log.Println("[ProveRemoveLiquidity] err info:", err)
			return err.Error()
		}
		removeLiquidityTx := &RemoveLiquidityTxInfo{
			PairIndex:     segment.PairIndex,
			AccountIndex:  segment.AccountIndex,
			AssetAId:      segment.AssetAId,
			AssetBId:      segment.AssetBId,
			MinB_A_Delta:  segment.MinB_A_Delta,
			MinB_B_Delta:  segment.MinB_B_Delta,
			Delta_LP:      segment.Delta_LP,
			GasFeeAssetId: segment.GasFeeAssetId,
			GasFee:        segment.GasFee,
			Proof:         proof.String(),
		}
		txBytes, err := json.Marshal(removeLiquidityTx)
		if err != nil {
			log.Println("[ProveRemoveLiquidity] err info: ", ErrMarshalTx)
			return ErrMarshalTx
		}
		return base64.StdEncoding.EncodeToString(txBytes)
	})
	return proveRemoveLiquidityFunc
}
