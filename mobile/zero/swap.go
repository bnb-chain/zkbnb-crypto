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
)

/*
	ProveSwap: helper function for the frontend for building swap tx
	@segmentInfo: segmentInfo JSON string
*/
func ProveSwap(segmentInfo string) (txInfo string, err error) {
	// parse segmentInfo
	segment, err := FromSwapSegmentJSON(segmentInfo)
	if err != nil {
		return "", err
	}
	// create withdraw relation
	relation, err := zero.NewSwapRelation(
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
		return "", err
	}
	// create withdraw proof
	proof, err := zero.ProveSwap(relation)
	if err != nil {
		return "", err
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
		return "", err
	}
	return base64.StdEncoding.EncodeToString(txBytes), nil
}
