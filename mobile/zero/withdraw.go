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
	ProveWithdraw: helper function for the frontend for building withdraw tx
	@segmentInfo: segmentInfo JSON string
*/
func ProveWithdraw(segmentInfo string) (txInfo string, err error) {
	// parse segmentInfo
	segment, err := FromWithdrawSegmentJSON(segmentInfo)
	if err != nil {
		log.Println("[ProveWithdraw] invalid params:", err)
		return "", err
	}
	// create withdraw relation
	relation, err := zero.NewWithdrawRelation(
		segment.ChainId,
		segment.C,
		segment.Pk,
		segment.B,
		segment.BStar,
		segment.Sk,
		segment.AssetId, segment.ReceiveAddr,
		segment.C_fee, segment.B_fee, segment.GasFeeAssetId, segment.GasFee,
	)
	if err != nil {
		log.Println("[ProveWithdraw] err info:", err)
		return "", err
	}
	// create withdraw proof
	proof, err := zero.ProveWithdraw(relation)
	if err != nil {
		log.Println("[ProveWithdraw] err info:", err)
		return "", err
	}
	withdrawTx := &WithdrawTxInfo{
		ChainId:       segment.ChainId,
		AssetId:       segment.AssetId,
		AccountIndex:  segment.AccountIndex,
		ReceiveAddr:   segment.ReceiveAddr,
		BStar:         segment.BStar,
		GasFeeAssetId: segment.GasFeeAssetId,
		GasFee:        segment.GasFee,
		Proof:         proof.String(),
	}
	txBytes, err := json.Marshal(withdrawTx)
	if err != nil {
		log.Println("[ProveWithdraw] err info:", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(txBytes), nil
}
