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

package main

import (
	"fmt"

	"syscall/js"

	"github.com/bnb-chain/zkbnb-crypto/wasm/legend/src"
)

/*
	zecrey-zero wasm libraries
*/

func main() {
	fmt.Println("ZkBNB Crypto Assembly")
	// util
	js.Global().Set("cleanPackedAmount", src.CleanPackedAmountUtil())
	js.Global().Set("cleanPackedFee", src.CleanPackedFeeUtil())
	// account
	js.Global().Set("getAccountNameHash", src.AccountNameHash())
	// eddsa
	js.Global().Set("getEddsaPublicKey", src.GetEddsaPublicKey())
	js.Global().Set("getEddsaCompressedPublicKey", src.GetEddsaCompressedPublicKey())
	js.Global().Set("generateEddsaKey", src.GenerateEddsaKey())
	js.Global().Set("eddsaSign", src.EddsaSign())
	js.Global().Set("eddsaVerify", src.EddsaVerify())

	// transaction
	// asset
	js.Global().Set("signAddLiquidity", src.AddLiquidityTx())
	js.Global().Set("signRemoveLiquidity", src.RemoveLiquidityTx())
	js.Global().Set("signSwap", src.SwapTx())
	js.Global().Set("signTransfer", src.TransferTx())
	js.Global().Set("signWithdraw", src.WithdrawTx())

	// nft
	js.Global().Set("signAtomicMatch", src.AtomicMatchTx())
	js.Global().Set("signCancelOffer", src.CancelOfferTx())
	js.Global().Set("signCreateCollection", src.CreateCollectionTx())
	js.Global().Set("signOffer", src.OfferTx())
	js.Global().Set("signMintNft", src.MintNftTx())
	js.Global().Set("signTransferNft", src.TransferNftTx())
	js.Global().Set("signWithdrawNft", src.WithdrawNftTx())
	<-make(chan bool)
}
