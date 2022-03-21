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

package zecrey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"log"
)

/*
	ProveAddLiquidity: add liquidity
	@segmentInfo: string JSON format
*/
func ProveAddLiquidity(segmentInfo string) (txInfo string, err error) {
	// parse segmentInfo
	segment, err := FromAddLiquiditySegmentJSON(segmentInfo)
	if err != nil {
		return "", err
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
		return "", err
	}
	proof, err := zecrey.ProveAddLiquidity(relation)
	if err != nil {
		log.Println("[ProveAddLiquidity] err info:", err)
		return "", err
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
		return "", errors.New(ErrMarshalTx)
	}
	return base64.StdEncoding.EncodeToString(txBytes), nil
}
