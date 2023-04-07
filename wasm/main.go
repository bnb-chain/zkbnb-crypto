/*
 * Copyright © 2022 ZkBNB Protocol
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

package main

import (
	"fmt"

	"syscall/js"

	src2 "github.com/bnb-chain/zkbnb-crypto/wasm/src"
)

/*
	zkbnb wasm libraries
*/

func main() {
	fmt.Println("ZkBNB Crypto Assembly")
	// util
	js.Global().Set("cleanPackedAmount", src2.CleanPackedAmountUtil())
	js.Global().Set("cleanPackedFee", src2.CleanPackedFeeUtil())
	// eddsa
	js.Global().Set("getEddsaPublicKey", src2.GetEddsaPublicKey())
	js.Global().Set("getEddsaCompressedPublicKey", src2.GetEddsaCompressedPublicKey())
	js.Global().Set("generateEddsaKey", src2.GenerateEddsaKey())
	js.Global().Set("eddsaSign", src2.EddsaSign())
	js.Global().Set("eddsaVerify", src2.EddsaVerify())

	// transaction
	js.Global().Set("signChangePubKeyTx", src2.ChangePubKeyTx())
	// asset
	js.Global().Set("signTransfer", src2.TransferTx())
	js.Global().Set("signWithdraw", src2.WithdrawTx())
	js.Global().Set("signChangePubKey", src2.ChangePubKeyTx())

	// nft
	js.Global().Set("signAtomicMatch", src2.AtomicMatchTx())
	js.Global().Set("signCancelOffer", src2.CancelOfferTx())
	js.Global().Set("signCreateCollection", src2.CreateCollectionTx())
	js.Global().Set("signOffer", src2.OfferTx())
	js.Global().Set("signMintNft", src2.MintNftTx())
	js.Global().Set("signTransferNft", src2.TransferNftTx())
	js.Global().Set("signWithdrawNft", src2.WithdrawNftTx())
	<-make(chan bool)
}
