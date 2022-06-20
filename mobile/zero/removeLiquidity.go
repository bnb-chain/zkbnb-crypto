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

package zero

import (
	"encoding/base64"
	"encoding/json"
	"github.com/bnb-chain/zkbas-crypto/zero/twistededwards/tebn254/zero"
	"log"
)

/*
	ProveRemoveLiquidity: remove liquidity
	@segmentInfo: string JSON format
*/
func ProveRemoveLiquidity(segmentInfo string) (txInfo string, err error) {
	// parse segmentInfo
	segment, err := FromRemoveLiquiditySegmentJSON(segmentInfo)
	if err != nil {
		return "", err
	}
	// check Balance is correct
	relation, err := zero.NewRemoveLiquidityRelation(
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
		return "", err
	}
	proof, err := zero.ProveRemoveLiquidity(relation)
	if err != nil {
		log.Println("[ProveRemoveLiquidity] err info:", err)
		return "", err
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
		return "", err
	}
	return base64.StdEncoding.EncodeToString(txBytes), nil
}
