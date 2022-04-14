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
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"log"
)

/*
	ProveUnlock: prove unlock
	@segmentInfoStr: string of segmentInfo, which is used to generate the unlock proof
*/
func ProveUnlock(segmentInfo string) (txInfo string, err error) {
	// parse segmentInfo: []TransferSegment
	segment, err := FromUnlockSegmentJSON(segmentInfo)
	if err != nil {
		log.Println("[FromUnlockSegmentJSON] err info:", err)
		return "", err
	}
	proof, err := zecrey.ProveUnlock(
		segment.Sk, segment.ChainId, segment.AssetId, segment.Balance, segment.DeltaAmount,
		segment.C_fee, segment.B_fee, segment.GasFeeAssetId, segment.GasFee,
	)
	if err != nil {
		log.Println("[FromUnlockSegmentJSON] err info:", err)
		return "", err
	}
	tx := &UnlockTxInfo{
		ChainId:       segment.ChainId,
		AccountIndex:  segment.AccountIndex,
		AssetId:       segment.AssetId,
		GasFeeAssetId: segment.GasFeeAssetId,
		GasFee:        segment.GasFee,
		DeltaAmount:   segment.DeltaAmount,
		// unlock proof
		Proof: proof.String(),
	}
	txBytes, err := json.Marshal(tx)
	if err != nil {
		log.Println("[FromUnlockSegmentJSON] err info:", err.Error())
		return "", err
	}
	return base64.StdEncoding.EncodeToString(txBytes), nil
}
