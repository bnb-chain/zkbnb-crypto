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

package circuit

import (
	"encoding/json"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

func TestVerifyBlock_Withdraw(t *testing.T) {
	blockInfo := `{"BlockNumber":17,"CreatedAt":1654746164165,"OldStateRoot":"DFmdIS7TZB4Lbfc16LBN1iesz9r7v6OMFzr18477Qz4=","NewStateRoot":"LUJc3cPVquxe0N0UZecDjn+7zGeeSkxsYgdCE075NxQ=","BlockCommitment":"D1xmfMH1nWaIHYtKFwNbX5wEmb6+1Q8yUcZUdWH4sHY=","Txs":[{"TxType":10,"RegisterZnsTxInfo":null,"CreatePairTxInfo":null,"UpdatePairRateTxInfo":null,"DepositTxInfo":null,"DepositNftTxInfo":null,"TransferTxInfo":null,"SwapTxInfo":null,"AddLiquidityTxInfo":null,"RemoveLiquidityTxInfo":null,"CreateCollectionTxInfo":null,"MintNftTxInfo":null,"TransferNftTxInfo":null,"AtomicMatchTxInfo":null,"CancelOfferTxInfo":null,"WithdrawTxInfo":{"FromAccountIndex":2,"AssetId":0,"AssetAmount":10000000,"GasAccountIndex":1,"GasFeeAssetId":2,"GasFeeAssetAmount":16001,"ToAddress":877323207452007368430275690353814663585699076679},"WithdrawNftTxInfo":null,"FullExitTxInfo":null,"FullExitNftTxInfo":null,"Nonce":2,"ExpiredAt":1654751859664,"Signature":{"R":{"X":"8883143774951925360568726785059406097423423533373876293813957723007390155837","Y":"12667755151030769718029106485750683780359440410737045189108574058946238576415"},"S":[2,21,127,57,48,114,120,145,140,1,135,215,183,80,235,119,61,201,192,116,55,72,113,124,141,85,42,174,30,122,5,115]},"AccountRootBefore":"FCUtNASxtpw+yes1vQX67r55IlVgzbxHLspnmtme0yE=","AccountsInfoBefore":[{"AccountIndex":2,"AccountNameHash":"IUotevICLfruSdrbiZLT18Il2K42EJtTHChAbdaarUU=","AccountPk":{"A":{"X":"16000316721428110343701227410730855423513151297873989379351027426602611915114","Y":"2653620439085989544435664312149594192579867261688935172472095966179307796144"}},"Nonce":1,"CollectionNonce":0,"AssetRoot":"HNEBbiPZ5RSSilZ8yKTN3M5nsB6BcCHrkW7arH4WYkI=","AssetsInfo":[{"AssetId":0,"Balance":99999999999900000,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":2,"Balance":99999999999999995000,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":65535,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":65535,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0}]},{"AccountIndex":1,"AccountNameHash":"CkjpiSpFoE0MWw8jWjrrB7khN7pxpZucRXd0uv3pWYM=","AccountPk":{"A":{"X":"19965822911226554215779061565234345854457524215316903843664120688444160684410","Y":"8734016109108763008334396672504977758060680100901855772709016788881531390238"}},"Nonce":0,"CollectionNonce":0,"AssetRoot":"COfJoYWPatmYaIdCb93ccjGpOoBsgbWEEXHsXLg06r4=","AssetsInfo":[{"AssetId":2,"Balance":5000,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":65535,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":65535,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":65535,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0}]},{"AccountIndex":4294967295,"AccountNameHash":"","AccountPk":{"A":{"X":0,"Y":0}},"Nonce":0,"CollectionNonce":0,"AssetRoot":"LGQtxKyLAhFUtCSMSrSgsPvP68FVfswhj8OjwZ7Of0c=","AssetsInfo":[{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0}]},{"AccountIndex":4294967295,"AccountNameHash":"","AccountPk":{"A":{"X":0,"Y":0}},"Nonce":0,"CollectionNonce":0,"AssetRoot":"LGQtxKyLAhFUtCSMSrSgsPvP68FVfswhj8OjwZ7Of0c=","AssetsInfo":[{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0}]},{"AccountIndex":4294967295,"AccountNameHash":"","AccountPk":{"A":{"X":0,"Y":0}},"Nonce":0,"CollectionNonce":0,"AssetRoot":"LGQtxKyLAhFUtCSMSrSgsPvP68FVfswhj8OjwZ7Of0c=","AssetsInfo":[{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0},{"AssetId":0,"Balance":0,"LpAmount":0,"OfferCanceledOrFinalized":0}]}],"LiquidityRootBefore":"CJIfZiZGWFxeuB9k1u0OIjv/OF1EKlARzHax3h52AcY=","LiquidityBefore":{"PairIndex":65535,"AssetAId":0,"AssetA":0,"AssetBId":0,"AssetB":0,"LpAmount":0,"KLast":0,"FeeRate":0,"TreasuryAccountIndex":0,"TreasuryRate":0},"NftRootBefore":"HLfliVWdhLHv2y1iAkOZsFhFEkHF20VuazI8OBGfsYs=","NftBefore":{"NftIndex":1099511627775,"NftContentHash":"AA==","CreatorAccountIndex":0,"OwnerAccountIndex":0,"NftL1Address":0,"NftL1TokenId":0,"CreatorTreasuryRate":0,"CollectionId":0},"StateRootBefore":"DFmdIS7TZB4Lbfc16LBN1iesz9r7v6OMFzr18477Qz4=","MerkleProofsAccountAssetsBefore":[[["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JoI79I8ThJVLo8j714O9UwFG1ZeVfNxix6wS6Pko5Tk=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","LnzPwI7i18Z9MJwIkPSU3HBMEssHVLbSCNd4fP4q+d8=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HQHuYAsoyvJqR3DQmT/oEsmB3LfIcs3EJ9Pe9H7FkfI="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HQHuYAsoyvJqR3DQmT/oEsmB3LfIcs3EJ9Pe9H7FkfI="]],[["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","ITjnB4s9cg5Bm86ZLMbHjxafIaDFDsi7aklZ4Ho93EA="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","ITjnB4s9cg5Bm86ZLMbHjxafIaDFDsi7aklZ4Ho93EA="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","ITjnB4s9cg5Bm86ZLMbHjxafIaDFDsi7aklZ4Ho93EA="]],[["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="]],[["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="]],[["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="],["Fl9O1pNe5xaeHvFkWg2OA6wuRJfM/K8c7SIeERFyY+o=","JAfzpXxtZ8VFKe3C1bB+VP28WcS45u0o1xLhJqhDlN0=","Dls7wUw/GgFcVIZnkxjlvfgXXn4p/qeJZujh3gTCDg8=","L6/vF7bRsn8QeeNUIX1XFugl4CtyafaQHXqhyqH1ieY=","ES6nIerclqcQsKXvASXmRmepQrNCU2RU99LZFcunT2g=","DFe8dmI7tSPoC+tudH6MfDrMwcvmOHe08jTb++Z7mqE=","D+zH0aVvynOFjfrIT2pnMYQTDzUd8YxQeHwhuVQQl8s=","DZ8dr3W+DuadEsZQMqVJKLB+h4eBnaKZpezcZtBd9lU=","E3OUUeRLBLY1zvQ7hhcQH7VeogkHoFWmy4eT73Ci2B4=","L8FnrG4EQDhtieT5oOR5waG9s362F+WoPbrmALVAZM0=","IxrMRGoZsQuY/8Xvdln1qukdTRZ2bWxURgIzOslbLXw=","IamM41cnP5fxla1ul+X4FN1P7r6x4WmSPzwrq7GY8w0=","BxAwzvSKIW+9DjRLemTc7py1bDs7iulBeB0GSM22XdE=","FG0OzfRK6ad3082FkKKADdwQRbFUiCzLSthxla/LQ8Y=","Dal4GBHjA1tY4OmYtd+K+HDC+pNzabG1XfjPbaSOee4=","HgzkMFPMkx20WsSt/HFMyyblh6EDNU7x3WFPC3YXVm4="]]],"MerkleProofsAccountBefore":[["FRjHpwI2HvEXODHP7irbre/bcemi0c6bx2hnWJ7VTuU=","CD6H1XNAXS2tm2cC+JWOtJ2hFnEXWs8arItmgNq4mA4=","F7dRxhJFGPh4M57Wzcmpdu642tP54v3fn8jB19+vrdQ=","FFCfIVcDkdFPu3CTCJKmoHdA1HuDpGbs7dk/vII3HMw=","CgdqgzBKsfg6tyuA3zlUhkymXjBmLJ0MUwGnkBCzci4=","Cuyoukaax3od364Ijwa6SXpPLfh6A9OIBPkkr5FC3HA=","DbRwvlIDOmj/YrMQ6RF27O5W5hg+d409gG9LVigrq6c=","DK0rGzCtaIPx4WTMHRLVRoFEWLrUWumD1GuRfAhHmbY=","CSsMXZRImLXI5P+YS75VgmfC/paTidXWvGoKc0JbA4Y=","AVRznOl2aujpg5GGt0fC/eHGXwpgmjg7GWhJuF3SLOo=","GaPjozj5f9sIz+r40MwYzRrfd24D9CrWuUnwSxFNmhI=","BCGEz1Pn3pLJ0dLkVLYHw5SDQKI95VXNZ9EJZzBRHa4=","E92rBHYsrjJmNnTlFG9z99xAw9R5sGQlTNM/SqlsKWc=","B6mLHFNGcKsOuiPE3u6lk1G00yU4V/rvPe+UXLaL3u4=","BQCad9KGs43+6FtCxvINfHEoFckk7I9IDjsE0XnYIfI=","CJlJNddCzw5B+PzcBs9BmCi8VIGLnQo93dZkVXQ7Yz8=","BhmYlYyI92oegy6wNVi/bdq8d/LRJO+AU6CUIjSBeEs=","Dxq/QJzr5D6KXTfPCXV/dSFXnlhpOaJMw949ZFW3eWs=","CoFqAE0N6guzQ6zPW5kCX3pQAkoZ01jkjtMn5gSVaCU=","H08+9KiBEnhBKjbiEOJkRYpm9aztHap7W3EUNNSPnXs=","F9TccPVBpOu36mX1Ofm1+VV5gR5SIDxvDMqAIMG7iVk=","LiuipCmW7iHl7Ykqs9f/zmxOGo3sCTLrALtuvdaIprA=","EzxCXMCn+12eJwhJ3GrzolIOD34Fw1iZYJHvK/3b75A=","B2HY7WPeU/Nowq2FmKi2C8NHSfvUbQCVhStM+lVTLz8=","LM+PhpJfSymrTBfwfMYCyBXPvQ7STWbuUa4NzgVqTJI=","FCMshvyNSWZY90lFKnEzGm0ICYMwvw0MD7eD5+QIIpQ=","AmPpBPn0u73O2F3ePY31eZbfv62DglHKuSX93zTN36Y=","H7AuLXuiTIY4wfEn9ZOBfdDZJtpJdqL8YcXHnEVO9Mo=","DjoUB5E00mXFpphtKl71soPp9pW1obdJneR5EDPz82A=","CkLknqQtfln1LdHj8r77VbQomSmnlBM5M0bSFCztpKU=","GofDA5wwLWsCR9LrMpSSyDk7jCVulQbLAlA0HyWkxO0=","HFa7+fbnhk4qM8p2N6Lbzd32ylZ7zQZThbVLVc1yTsI="],["B3ArIQ7Xwc8f3csK0LY9QNwD/j3NqRbg+JZSM6WpSqQ=","BIgNC8YD59fWAePFEp6SJGN65Kx/JJuqeo8e2Fl3PTw=","F7dRxhJFGPh4M57Wzcmpdu642tP54v3fn8jB19+vrdQ=","FFCfIVcDkdFPu3CTCJKmoHdA1HuDpGbs7dk/vII3HMw=","CgdqgzBKsfg6tyuA3zlUhkymXjBmLJ0MUwGnkBCzci4=","Cuyoukaax3od364Ijwa6SXpPLfh6A9OIBPkkr5FC3HA=","DbRwvlIDOmj/YrMQ6RF27O5W5hg+d409gG9LVigrq6c=","DK0rGzCtaIPx4WTMHRLVRoFEWLrUWumD1GuRfAhHmbY=","CSsMXZRImLXI5P+YS75VgmfC/paTidXWvGoKc0JbA4Y=","AVRznOl2aujpg5GGt0fC/eHGXwpgmjg7GWhJuF3SLOo=","GaPjozj5f9sIz+r40MwYzRrfd24D9CrWuUnwSxFNmhI=","BCGEz1Pn3pLJ0dLkVLYHw5SDQKI95VXNZ9EJZzBRHa4=","E92rBHYsrjJmNnTlFG9z99xAw9R5sGQlTNM/SqlsKWc=","B6mLHFNGcKsOuiPE3u6lk1G00yU4V/rvPe+UXLaL3u4=","BQCad9KGs43+6FtCxvINfHEoFckk7I9IDjsE0XnYIfI=","CJlJNddCzw5B+PzcBs9BmCi8VIGLnQo93dZkVXQ7Yz8=","BhmYlYyI92oegy6wNVi/bdq8d/LRJO+AU6CUIjSBeEs=","Dxq/QJzr5D6KXTfPCXV/dSFXnlhpOaJMw949ZFW3eWs=","CoFqAE0N6guzQ6zPW5kCX3pQAkoZ01jkjtMn5gSVaCU=","H08+9KiBEnhBKjbiEOJkRYpm9aztHap7W3EUNNSPnXs=","F9TccPVBpOu36mX1Ofm1+VV5gR5SIDxvDMqAIMG7iVk=","LiuipCmW7iHl7Ykqs9f/zmxOGo3sCTLrALtuvdaIprA=","EzxCXMCn+12eJwhJ3GrzolIOD34Fw1iZYJHvK/3b75A=","B2HY7WPeU/Nowq2FmKi2C8NHSfvUbQCVhStM+lVTLz8=","LM+PhpJfSymrTBfwfMYCyBXPvQ7STWbuUa4NzgVqTJI=","FCMshvyNSWZY90lFKnEzGm0ICYMwvw0MD7eD5+QIIpQ=","AmPpBPn0u73O2F3ePY31eZbfv62DglHKuSX93zTN36Y=","H7AuLXuiTIY4wfEn9ZOBfdDZJtpJdqL8YcXHnEVO9Mo=","DjoUB5E00mXFpphtKl71soPp9pW1obdJneR5EDPz82A=","CkLknqQtfln1LdHj8r77VbQomSmnlBM5M0bSFCztpKU=","GofDA5wwLWsCR9LrMpSSyDk7jCVulQbLAlA0HyWkxO0=","HFa7+fbnhk4qM8p2N6Lbzd32ylZ7zQZThbVLVc1yTsI="],["JeQ/NE5en/WOv8VV8ClDyK5ycSPL6CvuAJPy7yi62P4=","Eh1IvP99Pdt7Lj5bY6PNqh2btpavgF5fnsXbV2BxcAE=","F7dRxhJFGPh4M57Wzcmpdu642tP54v3fn8jB19+vrdQ=","FFCfIVcDkdFPu3CTCJKmoHdA1HuDpGbs7dk/vII3HMw=","CgdqgzBKsfg6tyuA3zlUhkymXjBmLJ0MUwGnkBCzci4=","Cuyoukaax3od364Ijwa6SXpPLfh6A9OIBPkkr5FC3HA=","DbRwvlIDOmj/YrMQ6RF27O5W5hg+d409gG9LVigrq6c=","DK0rGzCtaIPx4WTMHRLVRoFEWLrUWumD1GuRfAhHmbY=","CSsMXZRImLXI5P+YS75VgmfC/paTidXWvGoKc0JbA4Y=","AVRznOl2aujpg5GGt0fC/eHGXwpgmjg7GWhJuF3SLOo=","GaPjozj5f9sIz+r40MwYzRrfd24D9CrWuUnwSxFNmhI=","BCGEz1Pn3pLJ0dLkVLYHw5SDQKI95VXNZ9EJZzBRHa4=","E92rBHYsrjJmNnTlFG9z99xAw9R5sGQlTNM/SqlsKWc=","B6mLHFNGcKsOuiPE3u6lk1G00yU4V/rvPe+UXLaL3u4=","BQCad9KGs43+6FtCxvINfHEoFckk7I9IDjsE0XnYIfI=","CJlJNddCzw5B+PzcBs9BmCi8VIGLnQo93dZkVXQ7Yz8=","BhmYlYyI92oegy6wNVi/bdq8d/LRJO+AU6CUIjSBeEs=","Dxq/QJzr5D6KXTfPCXV/dSFXnlhpOaJMw949ZFW3eWs=","CoFqAE0N6guzQ6zPW5kCX3pQAkoZ01jkjtMn5gSVaCU=","H08+9KiBEnhBKjbiEOJkRYpm9aztHap7W3EUNNSPnXs=","F9TccPVBpOu36mX1Ofm1+VV5gR5SIDxvDMqAIMG7iVk=","LiuipCmW7iHl7Ykqs9f/zmxOGo3sCTLrALtuvdaIprA=","EzxCXMCn+12eJwhJ3GrzolIOD34Fw1iZYJHvK/3b75A=","B2HY7WPeU/Nowq2FmKi2C8NHSfvUbQCVhStM+lVTLz8=","LM+PhpJfSymrTBfwfMYCyBXPvQ7STWbuUa4NzgVqTJI=","FCMshvyNSWZY90lFKnEzGm0ICYMwvw0MD7eD5+QIIpQ=","AmPpBPn0u73O2F3ePY31eZbfv62DglHKuSX93zTN36Y=","H7AuLXuiTIY4wfEn9ZOBfdDZJtpJdqL8YcXHnEVO9Mo=","DjoUB5E00mXFpphtKl71soPp9pW1obdJneR5EDPz82A=","CkLknqQtfln1LdHj8r77VbQomSmnlBM5M0bSFCztpKU=","GofDA5wwLWsCR9LrMpSSyDk7jCVulQbLAlA0HyWkxO0=","IXwRVSPLRdMEbF6PEqRGS4Kn6LQMHovm16QIIUtdfTY="],["JeQ/NE5en/WOv8VV8ClDyK5ycSPL6CvuAJPy7yi62P4=","Eh1IvP99Pdt7Lj5bY6PNqh2btpavgF5fnsXbV2BxcAE=","F7dRxhJFGPh4M57Wzcmpdu642tP54v3fn8jB19+vrdQ=","FFCfIVcDkdFPu3CTCJKmoHdA1HuDpGbs7dk/vII3HMw=","CgdqgzBKsfg6tyuA3zlUhkymXjBmLJ0MUwGnkBCzci4=","Cuyoukaax3od364Ijwa6SXpPLfh6A9OIBPkkr5FC3HA=","DbRwvlIDOmj/YrMQ6RF27O5W5hg+d409gG9LVigrq6c=","DK0rGzCtaIPx4WTMHRLVRoFEWLrUWumD1GuRfAhHmbY=","CSsMXZRImLXI5P+YS75VgmfC/paTidXWvGoKc0JbA4Y=","AVRznOl2aujpg5GGt0fC/eHGXwpgmjg7GWhJuF3SLOo=","GaPjozj5f9sIz+r40MwYzRrfd24D9CrWuUnwSxFNmhI=","BCGEz1Pn3pLJ0dLkVLYHw5SDQKI95VXNZ9EJZzBRHa4=","E92rBHYsrjJmNnTlFG9z99xAw9R5sGQlTNM/SqlsKWc=","B6mLHFNGcKsOuiPE3u6lk1G00yU4V/rvPe+UXLaL3u4=","BQCad9KGs43+6FtCxvINfHEoFckk7I9IDjsE0XnYIfI=","CJlJNddCzw5B+PzcBs9BmCi8VIGLnQo93dZkVXQ7Yz8=","BhmYlYyI92oegy6wNVi/bdq8d/LRJO+AU6CUIjSBeEs=","Dxq/QJzr5D6KXTfPCXV/dSFXnlhpOaJMw949ZFW3eWs=","CoFqAE0N6guzQ6zPW5kCX3pQAkoZ01jkjtMn5gSVaCU=","H08+9KiBEnhBKjbiEOJkRYpm9aztHap7W3EUNNSPnXs=","F9TccPVBpOu36mX1Ofm1+VV5gR5SIDxvDMqAIMG7iVk=","LiuipCmW7iHl7Ykqs9f/zmxOGo3sCTLrALtuvdaIprA=","EzxCXMCn+12eJwhJ3GrzolIOD34Fw1iZYJHvK/3b75A=","B2HY7WPeU/Nowq2FmKi2C8NHSfvUbQCVhStM+lVTLz8=","LM+PhpJfSymrTBfwfMYCyBXPvQ7STWbuUa4NzgVqTJI=","FCMshvyNSWZY90lFKnEzGm0ICYMwvw0MD7eD5+QIIpQ=","AmPpBPn0u73O2F3ePY31eZbfv62DglHKuSX93zTN36Y=","H7AuLXuiTIY4wfEn9ZOBfdDZJtpJdqL8YcXHnEVO9Mo=","DjoUB5E00mXFpphtKl71soPp9pW1obdJneR5EDPz82A=","CkLknqQtfln1LdHj8r77VbQomSmnlBM5M0bSFCztpKU=","GofDA5wwLWsCR9LrMpSSyDk7jCVulQbLAlA0HyWkxO0=","IXwRVSPLRdMEbF6PEqRGS4Kn6LQMHovm16QIIUtdfTY="],["JeQ/NE5en/WOv8VV8ClDyK5ycSPL6CvuAJPy7yi62P4=","Eh1IvP99Pdt7Lj5bY6PNqh2btpavgF5fnsXbV2BxcAE=","F7dRxhJFGPh4M57Wzcmpdu642tP54v3fn8jB19+vrdQ=","FFCfIVcDkdFPu3CTCJKmoHdA1HuDpGbs7dk/vII3HMw=","CgdqgzBKsfg6tyuA3zlUhkymXjBmLJ0MUwGnkBCzci4=","Cuyoukaax3od364Ijwa6SXpPLfh6A9OIBPkkr5FC3HA=","DbRwvlIDOmj/YrMQ6RF27O5W5hg+d409gG9LVigrq6c=","DK0rGzCtaIPx4WTMHRLVRoFEWLrUWumD1GuRfAhHmbY=","CSsMXZRImLXI5P+YS75VgmfC/paTidXWvGoKc0JbA4Y=","AVRznOl2aujpg5GGt0fC/eHGXwpgmjg7GWhJuF3SLOo=","GaPjozj5f9sIz+r40MwYzRrfd24D9CrWuUnwSxFNmhI=","BCGEz1Pn3pLJ0dLkVLYHw5SDQKI95VXNZ9EJZzBRHa4=","E92rBHYsrjJmNnTlFG9z99xAw9R5sGQlTNM/SqlsKWc=","B6mLHFNGcKsOuiPE3u6lk1G00yU4V/rvPe+UXLaL3u4=","BQCad9KGs43+6FtCxvINfHEoFckk7I9IDjsE0XnYIfI=","CJlJNddCzw5B+PzcBs9BmCi8VIGLnQo93dZkVXQ7Yz8=","BhmYlYyI92oegy6wNVi/bdq8d/LRJO+AU6CUIjSBeEs=","Dxq/QJzr5D6KXTfPCXV/dSFXnlhpOaJMw949ZFW3eWs=","CoFqAE0N6guzQ6zPW5kCX3pQAkoZ01jkjtMn5gSVaCU=","H08+9KiBEnhBKjbiEOJkRYpm9aztHap7W3EUNNSPnXs=","F9TccPVBpOu36mX1Ofm1+VV5gR5SIDxvDMqAIMG7iVk=","LiuipCmW7iHl7Ykqs9f/zmxOGo3sCTLrALtuvdaIprA=","EzxCXMCn+12eJwhJ3GrzolIOD34Fw1iZYJHvK/3b75A=","B2HY7WPeU/Nowq2FmKi2C8NHSfvUbQCVhStM+lVTLz8=","LM+PhpJfSymrTBfwfMYCyBXPvQ7STWbuUa4NzgVqTJI=","FCMshvyNSWZY90lFKnEzGm0ICYMwvw0MD7eD5+QIIpQ=","AmPpBPn0u73O2F3ePY31eZbfv62DglHKuSX93zTN36Y=","H7AuLXuiTIY4wfEn9ZOBfdDZJtpJdqL8YcXHnEVO9Mo=","DjoUB5E00mXFpphtKl71soPp9pW1obdJneR5EDPz82A=","CkLknqQtfln1LdHj8r77VbQomSmnlBM5M0bSFCztpKU=","GofDA5wwLWsCR9LrMpSSyDk7jCVulQbLAlA0HyWkxO0=","IXwRVSPLRdMEbF6PEqRGS4Kn6LQMHovm16QIIUtdfTY="]],"MerkleProofsLiquidityBefore":["K7+qXDdyb8QEfUNgBbBCbmsn1No+I/wvVVNTgJFFCu4=","IIfUEShUrb7XfTqCrWI5LP6d9gHSEBz5FOPvgvKScd4=","E2c0KkNDPzWgyFPBaHNF29xAz3s1FAt+kcyj9s6nFS0=","FLBhmlnbIiOVryDfUYJpS4Dnt371c2F/EYSgzA7lo1M=","APy96pIkYJFtXqJ7O5HrxjBI44MJSk4PVTJUuyN7zWA=","Bn+BGjl/gguAi9oVt5Gm+EepV8U/v2yhta2xG+ejytM=","DWBfLs73K+SYuHoimVTRKTbgHR+uj3lkvmOdb6aEgdM=","IzK2g3g5wDv24Sz+G5x41F1uYLLp2DRqR3CWhzXTdC8=","L5GzaYD8N8RWiYf6X+ny/kjRdj16p8AYJNEL5Uw7Rx8=","KwooHgbNLZq7lSTqvMPL6FF7sOfFgLa35znNKFjH52k=","KjmlMFbkg0PCjJ+8cWBQuRsDGoy1KWWJHzW+57xZ6UA=","DsXOpperKwZLwA+ILJRiYvqNg1ZPpvmSXc26eKboGNo=","AI+7jOMvJ6PL0Vkx/0VLanZcGx43gdS0CwGaUhxZuyE=","KTEMRCrl8YOqo+PjwmfmA8ksQlW6AFwn0BbrJWQKQkQ=","FmNXf+pm0F8Jod65XhwoUyaVA+GQiv/mBJNpHo2HVCU=","H7mKuJbCSCTIA3frm/LzlGkUM/aGEyg77IPhN0pUftI="],"MerkleProofsNftBefore":["FVkaFudltLOe+OsfziQEq77RqXY/MggqhCtvISVuwpw=","A2uWya9IYtzt8JzBMkLPeoc/sffv2SVIQoC4RhbOHeU=","Dg/tHovhKRFQtO94Jvqq3sCDzsYQbJhfXebWwSAjFsA=","KQ3lsCbPQ2C22NBO23mYF1FnG+PHwoqgCpYmL4HJ+dc=","LoumvAY0R/poMwDAMTmtWwX6KZBkPtpWmYRkWlBurE4=","ME4BonXX4HBdFSVLcTPcuLDoVFtTepSTYj5wP8uOCZs=","G3YN1p1lEOBB6pLRsAt1rjJ440g/Xx6xsy+VBmvKCZ8=","IRtmGbK7V1mkH1o1rw7faX0j7z/pw8myk26wxsDV0vs=","Bes0PnZM9B+x0jUprAMTHkQvt742Ip2eh5SmQ/GmKsA=","H4P+xPOjQK54bp3CS2BkUeuDh/TyyxWIX3Pck5S3IWg=","L7xWEvWn/pa7TTHayQxh+X9G8wqWa3MdQ+9qEeF9LF8=","AIapFuKSSQRaikic4cgzFE3itQ+dEUR9C9Zq3oaLctQ=","BM8XEVLq/VVaYkD2j+ZmxhLXmWFjpui1qbIpaYQOQ1g=","Ba7cwh9AEb5Bs3ANMb7qIjIeWBf3+TMo2XJYfrZ3IKE=","GvChRX7ClAfTTYcrbwUZWs50AqVgbI+Plq7MDODCiks=","A7bzE1DwAaQwExwwbNBnSaEKJgJGrsaQ/MZDp4xLnSs=","HBSU5hRa0hpYp/g8Sav3x0TXuOUTbzfTmP6lzHrPi0k=","DNsV4u5xPuGkIJxgANPZcbkDgrNufUAFKQ5wWXYWyNc=","DsYiQ7Yjgppqor/9sBXg+W91ZMGE6jikMZ5N7yBkB5U=","BTR8DbLkkPdBf8SiEC16R6xieAbeJDCE/1W/Lc+7AiU=","B7mwbiTF+OohyZkUaPNvP39PdNt6XCTTly1mpbRj0ck=","Gw63RebtQdnSxY0SyZhEPRJjNHpAgdqNepaZ1p7T55M=","ClfUq/YDOJGiZqYvERAi7HZDq55+bsqAiYZob91FmvA=","GwAAZHBrAQfnKCZaBUnox3JFP1vRfduY84OUdvP1eLY=","AfSlczqCeDJ9pv6JrmJaKTAuzhO9OKSRsyWnKoqeY2w=","IRPFkGtmoho5NPHJGCF5aB+K9biMoy2Mdn4C8KPQwjg=","FOWzkzph+L1SWBEaMJ8F1feIkUCYaiq8s304Xn8AqGA=","IscDSHdkLq96LetJ9RYLsrhYCR4a9D1csHsdgZGdZ7Q=","EoM22NXN7pN87wcku7MkgV5Ze//83t1Xyvz1BLpVzDQ=","LhitKiKMXnJPtxWjaXvRkC6J8FRtu+7nPv0iIFtjC7M=","LvX/TUySjvLPUTopYmmyrxxSuRB3YLaqVD9Uno7TMxs=","J0pCb0NiJbcpcR7Yc03TRxD4ieYgyg2A95HcS12aAoQ=","CBJtNkLhyfJvIqz6IbOwhXn8ClV7wiVmggdKgPTyoFk=","CpJk12XKhGer7aXzXX+otOvJDOBdW5AbeElcLNWR56Y=","EPAwUuM2eAJ4FVlzriEyAYwCd949Qtn/u9n4CmscduY=","HbrzTJSDOqlFWm9XnW1UwfAJIz9NAfpOLrQxdyuJ3OU=","BNpvGWruCLDhgEA0OiGCjag7CbGT49JDx4GmzloRv4Q=","JLny/cDxYKXPNTvUQCbsQJYMucR8cG1XEn+B6cLgKnA=","LEuLSXcXG4NdSdpZtbbnk7JQtEjPQUSR39KIM4dsdSw=","LhWtZ+W+WPuxXXjVTLJ6bdvmskTg7VOeUd27ug0QN4E="],"StateRootAfter":"LUJc3cPVquxe0N0UZecDjn+7zGeeSkxsYgdCE075NxQ="}]}`
	var oBlock *Block
	err := json.Unmarshal([]byte(blockInfo), &oBlock)
	if err != nil {
		panic(err)
	}
	assert := test.NewAssert(t)
	var circuit, witness BlockConstraints
	witness, err = SetBlockWitness(oBlock)
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(
		&circuit, &witness, test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.WithProverOpts(backend.WithHints(types.Keccak256)),
		test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}
