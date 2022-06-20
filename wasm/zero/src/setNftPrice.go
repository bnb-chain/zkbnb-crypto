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
	"errors"
	"github.com/bnb-chain/zkbas-crypto/zero/twistededwards/tebn254/zero"
	"log"
	"syscall/js"
)

/*
	ProveSetNftPrice: helper function for the frontend for building set nft price tx
	@segmentInfo: segmentInfo JSON string
*/
func ProveSetNftPrice() js.Func {
	proveFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 1
		if len(args) != 1 {
			log.Println("[ProveSetNftPrice] invalid size")
			return errors.New("[ProveSetNftPrice] invalid size").Error()
		}
		// read segmentInfo JSON str
		segmentInfo := args[0].String()
		// parse segmentInfo
		segment, errStr := FromSetNftPriceSegmentJSON(segmentInfo)
		if errStr != Success {
			log.Println("[ProveSetNftPrice] invalid params:", errStr)
			return errStr
		}
		// create withdraw relation
		relation, err := zero.NewSetNftPriceRelation(
			segment.Pk,
			SetNftPrice,
			segment.NftIndex,
			segment.AssetId,
			segment.AssetAmount,
			segment.Sk,
			segment.C_fee, segment.B_fee, segment.GasFeeAssetId, segment.GasFee,
		)
		if err != nil {
			log.Println("[ProveSetNftPrice] err info:", err)
			return ErrInvalidWithdrawRelationParams
		}
		// create withdraw proof
		proof, err := zero.ProveSetNftPrice(relation)
		if err != nil {
			log.Println("[ProveSetNftPrice] err info:", err)
			return err.Error()
		}
		tx := &SetNftPriceTxInfo{
			AccountIndex:  segment.AccountIndex,
			NftIndex:      segment.NftIndex,
			AssetId:       segment.AssetId,
			AssetAmount:   segment.AssetAmount,
			GasFeeAssetId: segment.GasFeeAssetId,
			GasFee:        segment.GasFee,
			Proof:         proof.String(),
		}
		txBytes, err := json.Marshal(tx)
		if err != nil {
			log.Println("[ProveSetNftPrice] err info:", err)
			return ErrMarshalTx
		}
		return base64.StdEncoding.EncodeToString(txBytes)
	})
	return proveFunc
}
