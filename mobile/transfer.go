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
	ProveTransfer: prove privacy transfer
	@AssetId: asset id
	@fee: fee
	@segmentInfosStr: string of segmentInfo array, which are used to generate the transfer proof
*/
func ProveTransfer(assetId int, gasFee int64, memo string, segmentInfosStr string) (txInfo string, err error) {
	// parse segmentInfo: []TransferSegment
	var segments []*TransferSegment
	segmentsStr, err := FromTransferSegmentJSON(segmentInfosStr)
	if err != nil {
		log.Println("[ProveTransfer] err info: ", err)
		return "", err
	}
	err = json.Unmarshal([]byte(segmentsStr), &segments)
	if err != nil {
		return "", err
	}
	relation, err := zecrey.NewTransferProofRelation(uint32(assetId), uint64(gasFee))
	if err != nil {
		log.Println("[ProveTransfer] err info: ", err)
		return "", err
	}
	// set up accountsIndex
	accountsIndex := make([]uint32, len(segments))
	for i, segment := range segments {
		accountsIndex[i] = segment.AccountIndex
		err = relation.AddStatement(segment.BalanceEnc, segment.Pk, segment.Balance, segment.BDelta, segment.Sk)
		if err != nil {
			log.Println("[ProveTransfer] err info: ", err)
			return "", err
		}
	}
	transferProof, err := zecrey.ProveTransfer(relation)
	if err != nil {
		log.Println("[ProveTransfer] err info: ", err)
		return "", err
	}
	tx := &TransferTxInfo{
		// token id
		AssetId: uint32(assetId),
		// account indexes
		AccountsIndex: accountsIndex,
		// GasFee
		GasFee: uint64(gasFee),
		// transfer proof
		Proof: transferProof.String(),
		Memo:  memo,
	}
	txBytes, err := json.Marshal(tx)
	if err != nil {
		log.Println("[ProveTransfer] err info: ", err.Error())
		return "", err
	}
	return base64.StdEncoding.EncodeToString(txBytes), nil
}
