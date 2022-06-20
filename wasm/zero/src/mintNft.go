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
	"github.com/ethereum/go-ethereum/common"
	"github.com/bnb-chain/zkbas-crypto/zero/twistededwards/tebn254/zero"
	"log"
	"syscall/js"
)

/*
	ProveMintNft: helper function for the frontend for building mint nft tx
	@segmentInfo: segmentInfo JSON string
*/
func ProveMintNft() js.Func {
	proveFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// length of args should be 1
		if len(args) != 1 {
			log.Println("[ProveMintNft] invalid size")
			return errors.New("[ProveMintNft] invalid size").Error()
		}
		// read segmentInfo JSON str
		segmentInfo := args[0].String()
		// parse segmentInfo
		segment, errStr := FromMintNftSegmentJSON(segmentInfo)
		if errStr != Success {
			log.Println("[ProveMintNft] invalid params:", errStr)
			return errStr
		}
		// compute content hash
		contentHash := zero.ComputeContentHash(segment.NftName, segment.NftUrl, segment.NftIntroduction, segment.NftAttributes)
		// create withdraw relation
		relation, err := zero.NewMintNftRelation(
			segment.Pk,
			MintNft,
			contentHash,
			segment.ReceiverAccountIndex,
			segment.Sk,
			segment.C_fee, segment.B_fee, segment.GasFeeAssetId, segment.GasFee,
		)
		if err != nil {
			log.Println("[ProveMintNft] err info:", err)
			return ErrInvalidWithdrawRelationParams
		}
		// create withdraw proof
		proof, err := zero.ProveMintNft(relation)
		if err != nil {
			log.Println("[ProveMintNft] err info:", err)
			return err.Error()
		}
		tx := &MintNftTxInfo{
			AccountIndex:         segment.AccountIndex,
			NftName:              segment.NftName,
			NftUrl:               segment.NftUrl,
			NftCollectionId:      segment.NftCollectionId,
			NftIntroduction:      segment.NftIntroduction,
			NftContentHash:       common.Bytes2Hex(contentHash),
			NftAttributes:        segment.NftAttributes,
			ReceiverAccountIndex: segment.ReceiverAccountIndex,
			GasFeeAssetId:        segment.GasFeeAssetId,
			GasFee:               segment.GasFee,
			Proof:                proof.String(),
		}
		txBytes, err := json.Marshal(tx)
		if err != nil {
			log.Println("[ProveMintNft] err info:", err)
			return ErrMarshalTx
		}
		return base64.StdEncoding.EncodeToString(txBytes)
	})
	return proveFunc
}
