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

package solidity

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/bnb-chain/zkbnb-crypto/circuit"
)

var (
	optionalBlockSizes = flag.String("blocksizes", "1,10", "block size that will be used for proof generation and verification")
	batchSize          = flag.Int("batchsize", 100000, "number of constraints in r1cs file")
	bN                 = flag.Int("bN", 0, "bN is the bits of N Hashes, if we got 1024 hashes to prove, the bN should be set to 10")
	createKeys         = flag.Bool("create_pkvk", true, "if false, the pk and vk will not be created and should be used from mpc setup ceremony")
)

func TestCompileCircuit(t *testing.T) {
	differentBlockSizes := optionalBlockSizesInt()
	gasAssetIds := []int64{0, 1}
	gasAccountIndex := int64(1)
	for i := 0; i < len(differentBlockSizes); i++ {
		var blockConstraints circuit.BlockConstraints
		blockConstraints.TxsCount = differentBlockSizes[i]
		blockConstraints.Txs = make([]circuit.TxConstraints, blockConstraints.TxsCount)
		for i := 0; i < blockConstraints.TxsCount; i++ {
			blockConstraints.Txs[i] = circuit.GetZeroTxConstraint()
		}
		blockConstraints.GasAssetIds = gasAssetIds
		blockConstraints.GasAccountIndex = gasAccountIndex
		bn := chooseBN(*bN, differentBlockSizes[i])
		blockConstraints.GKRs.AllocateGKRCircuit(bn)
		blockConstraints.Gas = circuit.GetZeroGasConstraints(gasAssetIds)
		oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &blockConstraints, frontend.IgnoreUnconstrainedInputs(), frontend.WithGKRBN(bn))
		if err != nil {
			panic(err)
		}
		t.Logf("Number of constraints: %d\n", oR1cs.GetNbConstraints())
	}
}

func TestExportSol(t *testing.T) {
	exportSol(t, optionalBlockSizesInt())
}

func TestExportSolSmall(t *testing.T) {
	differentBlockSizes := []int{1}
	exportSol(t, differentBlockSizes)
}

func exportSol(t *testing.T, differentBlockSizes []int) {
	gasAssetIds := []int64{0, 1}
	gasAccountIndex := int64(1)
	sessionName := "zkbnb"

	for i := 0; i < len(differentBlockSizes); i++ {
		var blockConstraints circuit.BlockConstraints
		blockConstraints.TxsCount = differentBlockSizes[i]
		blockConstraints.Txs = make([]circuit.TxConstraints, blockConstraints.TxsCount)
		for i := 0; i < blockConstraints.TxsCount; i++ {
			blockConstraints.Txs[i] = circuit.GetZeroTxConstraint()
		}
		blockConstraints.GasAssetIds = gasAssetIds
		blockConstraints.GasAccountIndex = gasAccountIndex
		blockConstraints.Gas = circuit.GetZeroGasConstraints(gasAssetIds)
		bn := chooseBN(*bN, differentBlockSizes[i])
		t.Logf("block size: %d, bN: %d", differentBlockSizes[i], bn)
		blockConstraints.GKRs.AllocateGKRCircuit(bn)

		oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &blockConstraints, frontend.IgnoreUnconstrainedInputs(), frontend.WithGKRBN(bn))
		if err != nil {
			panic(err)
		}
		t.Logf("Constraints num=%d\n", oR1cs.GetNbConstraints())
		nbPublicVariables := oR1cs.GetNbPublicVariables()
		nbSecretVariables := oR1cs.GetNbSecretVariables()
		nbInternalVariables := oR1cs.GetNbInternalVariables()
		t.Logf("Variables total=%d, nbPublicVariables=%d, nbSecretVariables=%d, nbInternalVariables=%d\n",
			nbPublicVariables+nbSecretVariables+nbInternalVariables, nbPublicVariables, nbSecretVariables, nbInternalVariables)

		if differentBlockSizes[i] == 1 {
			isSolved(oR1cs, t)
		}

		sessionNameForBlock := sessionName + fmt.Sprint(differentBlockSizes[i])
		oR1cs.Lazify()

		t.Logf("After lazify constraints num=%d, r1c=%d\n", oR1cs.GetNbConstraints(), oR1cs.GetNbR1C())
		err = oR1cs.SplitDumpBinary(sessionNameForBlock, *batchSize)

		oR1csFull := groth16.NewCS(ecc.BN254)
		oR1csFull.LoadFromSplitBinaryConcurrent(sessionNameForBlock, oR1cs.GetNbR1C(), *batchSize, runtime.NumCPU())
		if err != nil {
			panic(err)
		}

		f, err := os.Create(sessionNameForBlock + ".r1cslen")
		if err != nil {
			panic(err)
		}
		_, err = f.WriteString(fmt.Sprint(oR1csFull.GetNbR1C()))
		if err != nil {
			panic(err)
		}
		f.Close()

		if *createKeys {
			err = groth16.SetupDumpKeys(oR1csFull, sessionNameForBlock)
			if err != nil {
				panic(err)
			}

			{
				verifyingKey := groth16.NewVerifyingKey(ecc.BN254)
				f, _ := os.Open(sessionNameForBlock + ".vk.save")
				_, err = verifyingKey.ReadFrom(f)
				if err != nil {
					panic(fmt.Errorf("read file error"))
				}
				f.Close()
				f, err := os.Create("ZkBNBVerifier" + fmt.Sprint(differentBlockSizes[i]) + ".sol")
				if err != nil {
					panic(err)
				}
				err = verifyingKey.ExportSolidity(f)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}

func isSolved(oR1cs constraint.ConstraintSystem, t *testing.T) {
	witnessJson := "{\"BlockNumber\":18,\"CreatedAt\":1681559486412,\"OldStateRoot\":\"Dhg1ijJq5CYOuH+Et0i9Lw+9tBy+XaNze4hBMHLwz2E=\",\"NewStateRoot\":\"GpMC+Nr1XWTjPnkh6+5L7x/8EpfcjaBk8GZaakjjYes=\",\"BlockCommitment\":\"d0UrRiAoK2EuSHqAVA7AtcGKzTpl5PpfSJmLhdMnF8U=\",\"Txs\":[{\"TxType\":4,\"ChangePubKeyTxInfo\":null,\"DepositTxInfo\":null,\"DepositNftTxInfo\":null,\"TransferTxInfo\":{\"FromAccountIndex\":1,\"ToAccountIndex\":2,\"ToL1Address\":\"PETN3bapAPorWF3SmeA9EvpCk7w=\",\"AssetId\":0,\"AssetAmount\":320000000000,\"GasAccountIndex\":1,\"GasFeeAssetId\":0,\"GasFeeAssetAmount\":32010,\"CallDataHash\":\"LHKY/YfTA5/+oghTj2spe2Czc6Y3krTNBlT9yI/Q1u4=\"},\"CreateCollectionTxInfo\":null,\"MintNftTxInfo\":null,\"TransferNftTxInfo\":null,\"AtomicMatchTxInfo\":null,\"CancelOfferTxInfo\":null,\"WithdrawTxInfo\":null,\"WithdrawNftTxInfo\":null,\"FullExitTxInfo\":null,\"FullExitNftTxInfo\":null,\"Nonce\":2,\"ExpiredAt\":1681560083242,\"Signature\":{\"R\":{\"X\":\"5113632115241758951633822276633481091830399974472715949435360190999318191257\",\"Y\":\"8179668887039872248149453977597938353024509853970844553492815796824228428248\"},\"S\":[0,245,236,157,104,103,66,60,183,182,4,147,46,72,216,162,105,89,222,120,74,112,25,0,194,250,141,108,209,27,20,60]},\"AccountRootBefore\":\"JAsk0zhXPzdMgpG2y3Rzyc5Hc60cWanx2ExTTAhVcyI=\",\"AccountsInfoBefore\":[{\"AccountIndex\":1,\"L1Address\":\"cJl5cMUYEtw6AQx9AbUODRfcecg=\",\"AccountPk\":{\"A\":{\"X\":\"8199190777948451040978801949301513350788178685232974699636521226139778292564\",\"Y\":\"17074878435405371424895458188552763456196723555144453459250457325008515674682\"}},\"Nonce\":2,\"CollectionNonce\":1,\"AssetRoot\":\"IB+tlDkt0ZCD7roeUP/MVNunlXScM8CK5yloUaUl1v0=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":20040000000000000,\"OfferCanceledOrFinalized\":0},{\"AssetId\":0,\"Balance\":20039990000000000,\"OfferCanceledOrFinalized\":0}]},{\"AccountIndex\":2,\"L1Address\":\"PETN3bapAPorWF3SmeA9EvpCk7w=\",\"AccountPk\":{\"A\":{\"X\":\"15098542031476477944907466275853943850483095174764377562107735442373795949897\",\"Y\":\"18633276793436517126110018435858869128721344196990958068587727806009371043561\"}},\"Nonce\":2,\"CollectionNonce\":1,\"AssetRoot\":\"DsO2wTfWIq6OeYEYwdEk6hBZ+dAz1Ped/qylevJIBQI=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":1980000000000000,\"OfferCanceledOrFinalized\":0},{\"AssetId\":65535,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]},{\"AccountIndex\":4294967295,\"L1Address\":\"\",\"AccountPk\":{\"A\":{\"X\":0,\"Y\":0}},\"Nonce\":0,\"CollectionNonce\":0,\"AssetRoot\":\"DBoi2Nx6jJ4QJJno2REqWxgAHrRAdEMRNxrCrmLeJCg=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0},{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]},{\"AccountIndex\":4294967295,\"L1Address\":\"\",\"AccountPk\":{\"A\":{\"X\":0,\"Y\":0}},\"Nonce\":0,\"CollectionNonce\":0,\"AssetRoot\":\"DBoi2Nx6jJ4QJJno2REqWxgAHrRAdEMRNxrCrmLeJCg=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0},{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]},{\"AccountIndex\":4294967295,\"L1Address\":\"\",\"AccountPk\":{\"A\":{\"X\":0,\"Y\":0}},\"Nonce\":0,\"CollectionNonce\":0,\"AssetRoot\":\"DBoi2Nx6jJ4QJJno2REqWxgAHrRAdEMRNxrCrmLeJCg=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0},{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]},{\"AccountIndex\":4294967295,\"L1Address\":\"\",\"AccountPk\":{\"A\":{\"X\":0,\"Y\":0}},\"Nonce\":0,\"CollectionNonce\":0,\"AssetRoot\":\"DBoi2Nx6jJ4QJJno2REqWxgAHrRAdEMRNxrCrmLeJCg=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0},{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]},{\"AccountIndex\":4294967295,\"L1Address\":\"\",\"AccountPk\":{\"A\":{\"X\":0,\"Y\":0}},\"Nonce\":0,\"CollectionNonce\":0,\"AssetRoot\":\"DBoi2Nx6jJ4QJJno2REqWxgAHrRAdEMRNxrCrmLeJCg=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0},{\"AssetId\":0,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]}],\"NftRootBefore\":\"Hbz87J3mvoKG/8tOSD4cIgv4iCG1UWnpeiGf31qYOT8=\",\"NftBefore\":{\"NftIndex\":1099511627775,\"NftContentHash\":\"AA==\",\"CreatorAccountIndex\":0,\"OwnerAccountIndex\":0,\"RoyaltyRate\":0,\"CollectionId\":0,\"NftContentType\":0},\"StateRootBefore\":\"Dhg1ijJq5CYOuH+Et0i9Lw+9tBy+XaNze4hBMHLwz2E=\",\"MerkleProofsAccountAssetsBefore\":[[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"]],[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"ExWAP5ZXc8hr3CXrFT2zeWcjnp4QNnI1zYyiQyobfr8=\"]],[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"]],[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"]],[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"]],[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"]],[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"],[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"]]],\"MerkleProofsAccountBefore\":[[\"BzsoPt8d13QfT7tu+HYIoGIc9S+ClP3Sg86ANlUnd1M=\",\"CDuC3s2aYFRAzNvWVs+oB1apVEVE71YGoN50T7FpDqQ=\",\"IFUVnze68EwhNRCEN0vzYKh8SckfflNewhEtvIdzutc=\",\"CMb1fGawYUtIRhyIh9/ZImdmmsoOMLscLwiTQTCzb1s=\",\"LWE3ax8IKR0C6jKr5j10HnfreqDoUcSaLjihEhre4CY=\",\"HRJ+ly6nheS0b4sAcPG4DdTJlISvATV1FOn6xAXxRk8=\",\"CDJB2XTSlVNBsF55aB2Wl9Hdr6b3oDBUd8lsUFAx5e4=\",\"DTs8Nv9Ea5NhIk8omEZAlrXycADBYvlstUo9e9ihxno=\",\"Hl/qGhWMyjgt5w4ES7R33xllk1Fuj+24pOBVcEIrkk0=\",\"LjPbg4FK8nDhYBgL0PicJSWgUPDEmhIrAkm4Wng6eeM=\",\"JqXGHSe9CoHlpk3F5OZFtml8D37R/G9yiZhg70HCMfQ=\",\"IRAYwiNHdfFe4FZlFQG/tEpm2ZYOKWQUjBiwWCbqXY4=\",\"APmoAKx+ra8o5CXUA1Tx1+ghBKZKWjH+gdS/rZheIrg=\",\"HvUxp5Rfp5QmadZxFrRKKLLEsNF1y0x/0ALaQUXwCLI=\",\"CjfVChSYAtfFm0QNai/fn+L4K7/7Ictko9M/w0BJMiw=\",\"AvGQPimrWouNgceQK3lO/tvK34vWBUEqey4oao0pQCY=\",\"LkcRfT+qHWTYomUreWneK2yry/xpMmPxcnRoTNtvp8E=\",\"HehQ8LbbtfijJDtvkW0eZV3SIsD018RIbob7kPVQsQs=\",\"BfvIDAEWgCIzkdTM5EJTqb2TrjX9BPSNCy67MbnCn48=\",\"HekARcIkSbfNwzLzUpMWCxNRPsi587b4gjVCxUYiflk=\",\"Ewmg/40pr1rYDyzzIlqauol+SswzZ5TVdSTz5SnfWmk=\",\"LLMGzLVXdCHGrXMca1LdTg1wsDI6ZY00MwcmiOwF4KQ=\",\"GODVGBMadOdZoJ6ypUDV0mMKcqV0UAwDmN9JmbmGi/w=\",\"CqXzBK1Ycc0K7ctzQg9x1A/s4Q6rb4QwBSZEssHBmGc=\",\"HnyavbxkomrbuPXQBjWRE4qI4dPOcJhIyd1PfVPKIxQ=\",\"KB6M8IhKV+iuWMJsAEmDreD23jR1zXtGv7wmkxXHHIY=\",\"D3+LN5RFyW0lrYZuF8dTthHcCNvSGQDIWtfU7J+r5PU=\",\"Ga3u1Cpnvdzb7wgqTUOlWZgRAiDUp9p80ZeT9LWhhq4=\",\"F9YrvUK51vd3qp+w1QXgraZcT0g6a8XcH9pOWTuKMmk=\",\"FbzTeQ9+s0b2kShF1UtNDV1dOX10CuHAcVI2bEgylL8=\",\"KXLj4Jhdr9E1fxCYpLM/DCBM4snTb6b8qxq9SWWggvY=\",\"If2BsNzorNWKcMAoLIx45kf6QFnV+sZVvscO9gbRLIQ=\"],[\"GBi7RX+i0Ej5DKwWnrUUHouFbQ3GnD5NUN3nbud5f4o=\",\"DCi0xPM5MJEA/lAQksBDpUKj3HoMEK6v8HCDT6C42o4=\",\"IFUVnze68EwhNRCEN0vzYKh8SckfflNewhEtvIdzutc=\",\"CMb1fGawYUtIRhyIh9/ZImdmmsoOMLscLwiTQTCzb1s=\",\"LWE3ax8IKR0C6jKr5j10HnfreqDoUcSaLjihEhre4CY=\",\"HRJ+ly6nheS0b4sAcPG4DdTJlISvATV1FOn6xAXxRk8=\",\"CDJB2XTSlVNBsF55aB2Wl9Hdr6b3oDBUd8lsUFAx5e4=\",\"DTs8Nv9Ea5NhIk8omEZAlrXycADBYvlstUo9e9ihxno=\",\"Hl/qGhWMyjgt5w4ES7R33xllk1Fuj+24pOBVcEIrkk0=\",\"LjPbg4FK8nDhYBgL0PicJSWgUPDEmhIrAkm4Wng6eeM=\",\"JqXGHSe9CoHlpk3F5OZFtml8D37R/G9yiZhg70HCMfQ=\",\"IRAYwiNHdfFe4FZlFQG/tEpm2ZYOKWQUjBiwWCbqXY4=\",\"APmoAKx+ra8o5CXUA1Tx1+ghBKZKWjH+gdS/rZheIrg=\",\"HvUxp5Rfp5QmadZxFrRKKLLEsNF1y0x/0ALaQUXwCLI=\",\"CjfVChSYAtfFm0QNai/fn+L4K7/7Ictko9M/w0BJMiw=\",\"AvGQPimrWouNgceQK3lO/tvK34vWBUEqey4oao0pQCY=\",\"LkcRfT+qHWTYomUreWneK2yry/xpMmPxcnRoTNtvp8E=\",\"HehQ8LbbtfijJDtvkW0eZV3SIsD018RIbob7kPVQsQs=\",\"BfvIDAEWgCIzkdTM5EJTqb2TrjX9BPSNCy67MbnCn48=\",\"HekARcIkSbfNwzLzUpMWCxNRPsi587b4gjVCxUYiflk=\",\"Ewmg/40pr1rYDyzzIlqauol+SswzZ5TVdSTz5SnfWmk=\",\"LLMGzLVXdCHGrXMca1LdTg1wsDI6ZY00MwcmiOwF4KQ=\",\"GODVGBMadOdZoJ6ypUDV0mMKcqV0UAwDmN9JmbmGi/w=\",\"CqXzBK1Ycc0K7ctzQg9x1A/s4Q6rb4QwBSZEssHBmGc=\",\"HnyavbxkomrbuPXQBjWRE4qI4dPOcJhIyd1PfVPKIxQ=\",\"KB6M8IhKV+iuWMJsAEmDreD23jR1zXtGv7wmkxXHHIY=\",\"D3+LN5RFyW0lrYZuF8dTthHcCNvSGQDIWtfU7J+r5PU=\",\"Ga3u1Cpnvdzb7wgqTUOlWZgRAiDUp9p80ZeT9LWhhq4=\",\"F9YrvUK51vd3qp+w1QXgraZcT0g6a8XcH9pOWTuKMmk=\",\"FbzTeQ9+s0b2kShF1UtNDV1dOX10CuHAcVI2bEgylL8=\",\"KXLj4Jhdr9E1fxCYpLM/DCBM4snTb6b8qxq9SWWggvY=\",\"If2BsNzorNWKcMAoLIx45kf6QFnV+sZVvscO9gbRLIQ=\"],[\"BCGmR8oAePZ7DJHWiGZxyj83fy8WLiodfCFfDld9Sns=\",\"JPfzZo6oNgAjlcLtuXa2jBfAJpUwv7EI1wGHQH2JwNM=\",\"IFUVnze68EwhNRCEN0vzYKh8SckfflNewhEtvIdzutc=\",\"CMb1fGawYUtIRhyIh9/ZImdmmsoOMLscLwiTQTCzb1s=\",\"LWE3ax8IKR0C6jKr5j10HnfreqDoUcSaLjihEhre4CY=\",\"HRJ+ly6nheS0b4sAcPG4DdTJlISvATV1FOn6xAXxRk8=\",\"CDJB2XTSlVNBsF55aB2Wl9Hdr6b3oDBUd8lsUFAx5e4=\",\"DTs8Nv9Ea5NhIk8omEZAlrXycADBYvlstUo9e9ihxno=\",\"Hl/qGhWMyjgt5w4ES7R33xllk1Fuj+24pOBVcEIrkk0=\",\"LjPbg4FK8nDhYBgL0PicJSWgUPDEmhIrAkm4Wng6eeM=\",\"JqXGHSe9CoHlpk3F5OZFtml8D37R/G9yiZhg70HCMfQ=\",\"IRAYwiNHdfFe4FZlFQG/tEpm2ZYOKWQUjBiwWCbqXY4=\",\"APmoAKx+ra8o5CXUA1Tx1+ghBKZKWjH+gdS/rZheIrg=\",\"HvUxp5Rfp5QmadZxFrRKKLLEsNF1y0x/0ALaQUXwCLI=\",\"CjfVChSYAtfFm0QNai/fn+L4K7/7Ictko9M/w0BJMiw=\",\"AvGQPimrWouNgceQK3lO/tvK34vWBUEqey4oao0pQCY=\",\"LkcRfT+qHWTYomUreWneK2yry/xpMmPxcnRoTNtvp8E=\",\"HehQ8LbbtfijJDtvkW0eZV3SIsD018RIbob7kPVQsQs=\",\"BfvIDAEWgCIzkdTM5EJTqb2TrjX9BPSNCy67MbnCn48=\",\"HekARcIkSbfNwzLzUpMWCxNRPsi587b4gjVCxUYiflk=\",\"Ewmg/40pr1rYDyzzIlqauol+SswzZ5TVdSTz5SnfWmk=\",\"LLMGzLVXdCHGrXMca1LdTg1wsDI6ZY00MwcmiOwF4KQ=\",\"GODVGBMadOdZoJ6ypUDV0mMKcqV0UAwDmN9JmbmGi/w=\",\"CqXzBK1Ycc0K7ctzQg9x1A/s4Q6rb4QwBSZEssHBmGc=\",\"HnyavbxkomrbuPXQBjWRE4qI4dPOcJhIyd1PfVPKIxQ=\",\"KB6M8IhKV+iuWMJsAEmDreD23jR1zXtGv7wmkxXHHIY=\",\"D3+LN5RFyW0lrYZuF8dTthHcCNvSGQDIWtfU7J+r5PU=\",\"Ga3u1Cpnvdzb7wgqTUOlWZgRAiDUp9p80ZeT9LWhhq4=\",\"F9YrvUK51vd3qp+w1QXgraZcT0g6a8XcH9pOWTuKMmk=\",\"FbzTeQ9+s0b2kShF1UtNDV1dOX10CuHAcVI2bEgylL8=\",\"KXLj4Jhdr9E1fxCYpLM/DCBM4snTb6b8qxq9SWWggvY=\",\"Ar59qhVwEtlpU5k+dEqUZPo9zdBccFgUx5zsVoOTG6c=\"],[\"BCGmR8oAePZ7DJHWiGZxyj83fy8WLiodfCFfDld9Sns=\",\"JPfzZo6oNgAjlcLtuXa2jBfAJpUwv7EI1wGHQH2JwNM=\",\"IFUVnze68EwhNRCEN0vzYKh8SckfflNewhEtvIdzutc=\",\"CMb1fGawYUtIRhyIh9/ZImdmmsoOMLscLwiTQTCzb1s=\",\"LWE3ax8IKR0C6jKr5j10HnfreqDoUcSaLjihEhre4CY=\",\"HRJ+ly6nheS0b4sAcPG4DdTJlISvATV1FOn6xAXxRk8=\",\"CDJB2XTSlVNBsF55aB2Wl9Hdr6b3oDBUd8lsUFAx5e4=\",\"DTs8Nv9Ea5NhIk8omEZAlrXycADBYvlstUo9e9ihxno=\",\"Hl/qGhWMyjgt5w4ES7R33xllk1Fuj+24pOBVcEIrkk0=\",\"LjPbg4FK8nDhYBgL0PicJSWgUPDEmhIrAkm4Wng6eeM=\",\"JqXGHSe9CoHlpk3F5OZFtml8D37R/G9yiZhg70HCMfQ=\",\"IRAYwiNHdfFe4FZlFQG/tEpm2ZYOKWQUjBiwWCbqXY4=\",\"APmoAKx+ra8o5CXUA1Tx1+ghBKZKWjH+gdS/rZheIrg=\",\"HvUxp5Rfp5QmadZxFrRKKLLEsNF1y0x/0ALaQUXwCLI=\",\"CjfVChSYAtfFm0QNai/fn+L4K7/7Ictko9M/w0BJMiw=\",\"AvGQPimrWouNgceQK3lO/tvK34vWBUEqey4oao0pQCY=\",\"LkcRfT+qHWTYomUreWneK2yry/xpMmPxcnRoTNtvp8E=\",\"HehQ8LbbtfijJDtvkW0eZV3SIsD018RIbob7kPVQsQs=\",\"BfvIDAEWgCIzkdTM5EJTqb2TrjX9BPSNCy67MbnCn48=\",\"HekARcIkSbfNwzLzUpMWCxNRPsi587b4gjVCxUYiflk=\",\"Ewmg/40pr1rYDyzzIlqauol+SswzZ5TVdSTz5SnfWmk=\",\"LLMGzLVXdCHGrXMca1LdTg1wsDI6ZY00MwcmiOwF4KQ=\",\"GODVGBMadOdZoJ6ypUDV0mMKcqV0UAwDmN9JmbmGi/w=\",\"CqXzBK1Ycc0K7ctzQg9x1A/s4Q6rb4QwBSZEssHBmGc=\",\"HnyavbxkomrbuPXQBjWRE4qI4dPOcJhIyd1PfVPKIxQ=\",\"KB6M8IhKV+iuWMJsAEmDreD23jR1zXtGv7wmkxXHHIY=\",\"D3+LN5RFyW0lrYZuF8dTthHcCNvSGQDIWtfU7J+r5PU=\",\"Ga3u1Cpnvdzb7wgqTUOlWZgRAiDUp9p80ZeT9LWhhq4=\",\"F9YrvUK51vd3qp+w1QXgraZcT0g6a8XcH9pOWTuKMmk=\",\"FbzTeQ9+s0b2kShF1UtNDV1dOX10CuHAcVI2bEgylL8=\",\"KXLj4Jhdr9E1fxCYpLM/DCBM4snTb6b8qxq9SWWggvY=\",\"Ar59qhVwEtlpU5k+dEqUZPo9zdBccFgUx5zsVoOTG6c=\"],[\"BCGmR8oAePZ7DJHWiGZxyj83fy8WLiodfCFfDld9Sns=\",\"JPfzZo6oNgAjlcLtuXa2jBfAJpUwv7EI1wGHQH2JwNM=\",\"IFUVnze68EwhNRCEN0vzYKh8SckfflNewhEtvIdzutc=\",\"CMb1fGawYUtIRhyIh9/ZImdmmsoOMLscLwiTQTCzb1s=\",\"LWE3ax8IKR0C6jKr5j10HnfreqDoUcSaLjihEhre4CY=\",\"HRJ+ly6nheS0b4sAcPG4DdTJlISvATV1FOn6xAXxRk8=\",\"CDJB2XTSlVNBsF55aB2Wl9Hdr6b3oDBUd8lsUFAx5e4=\",\"DTs8Nv9Ea5NhIk8omEZAlrXycADBYvlstUo9e9ihxno=\",\"Hl/qGhWMyjgt5w4ES7R33xllk1Fuj+24pOBVcEIrkk0=\",\"LjPbg4FK8nDhYBgL0PicJSWgUPDEmhIrAkm4Wng6eeM=\",\"JqXGHSe9CoHlpk3F5OZFtml8D37R/G9yiZhg70HCMfQ=\",\"IRAYwiNHdfFe4FZlFQG/tEpm2ZYOKWQUjBiwWCbqXY4=\",\"APmoAKx+ra8o5CXUA1Tx1+ghBKZKWjH+gdS/rZheIrg=\",\"HvUxp5Rfp5QmadZxFrRKKLLEsNF1y0x/0ALaQUXwCLI=\",\"CjfVChSYAtfFm0QNai/fn+L4K7/7Ictko9M/w0BJMiw=\",\"AvGQPimrWouNgceQK3lO/tvK34vWBUEqey4oao0pQCY=\",\"LkcRfT+qHWTYomUreWneK2yry/xpMmPxcnRoTNtvp8E=\",\"HehQ8LbbtfijJDtvkW0eZV3SIsD018RIbob7kPVQsQs=\",\"BfvIDAEWgCIzkdTM5EJTqb2TrjX9BPSNCy67MbnCn48=\",\"HekARcIkSbfNwzLzUpMWCxNRPsi587b4gjVCxUYiflk=\",\"Ewmg/40pr1rYDyzzIlqauol+SswzZ5TVdSTz5SnfWmk=\",\"LLMGzLVXdCHGrXMca1LdTg1wsDI6ZY00MwcmiOwF4KQ=\",\"GODVGBMadOdZoJ6ypUDV0mMKcqV0UAwDmN9JmbmGi/w=\",\"CqXzBK1Ycc0K7ctzQg9x1A/s4Q6rb4QwBSZEssHBmGc=\",\"HnyavbxkomrbuPXQBjWRE4qI4dPOcJhIyd1PfVPKIxQ=\",\"KB6M8IhKV+iuWMJsAEmDreD23jR1zXtGv7wmkxXHHIY=\",\"D3+LN5RFyW0lrYZuF8dTthHcCNvSGQDIWtfU7J+r5PU=\",\"Ga3u1Cpnvdzb7wgqTUOlWZgRAiDUp9p80ZeT9LWhhq4=\",\"F9YrvUK51vd3qp+w1QXgraZcT0g6a8XcH9pOWTuKMmk=\",\"FbzTeQ9+s0b2kShF1UtNDV1dOX10CuHAcVI2bEgylL8=\",\"KXLj4Jhdr9E1fxCYpLM/DCBM4snTb6b8qxq9SWWggvY=\",\"Ar59qhVwEtlpU5k+dEqUZPo9zdBccFgUx5zsVoOTG6c=\"],[\"BCGmR8oAePZ7DJHWiGZxyj83fy8WLiodfCFfDld9Sns=\",\"JPfzZo6oNgAjlcLtuXa2jBfAJpUwv7EI1wGHQH2JwNM=\",\"IFUVnze68EwhNRCEN0vzYKh8SckfflNewhEtvIdzutc=\",\"CMb1fGawYUtIRhyIh9/ZImdmmsoOMLscLwiTQTCzb1s=\",\"LWE3ax8IKR0C6jKr5j10HnfreqDoUcSaLjihEhre4CY=\",\"HRJ+ly6nheS0b4sAcPG4DdTJlISvATV1FOn6xAXxRk8=\",\"CDJB2XTSlVNBsF55aB2Wl9Hdr6b3oDBUd8lsUFAx5e4=\",\"DTs8Nv9Ea5NhIk8omEZAlrXycADBYvlstUo9e9ihxno=\",\"Hl/qGhWMyjgt5w4ES7R33xllk1Fuj+24pOBVcEIrkk0=\",\"LjPbg4FK8nDhYBgL0PicJSWgUPDEmhIrAkm4Wng6eeM=\",\"JqXGHSe9CoHlpk3F5OZFtml8D37R/G9yiZhg70HCMfQ=\",\"IRAYwiNHdfFe4FZlFQG/tEpm2ZYOKWQUjBiwWCbqXY4=\",\"APmoAKx+ra8o5CXUA1Tx1+ghBKZKWjH+gdS/rZheIrg=\",\"HvUxp5Rfp5QmadZxFrRKKLLEsNF1y0x/0ALaQUXwCLI=\",\"CjfVChSYAtfFm0QNai/fn+L4K7/7Ictko9M/w0BJMiw=\",\"AvGQPimrWouNgceQK3lO/tvK34vWBUEqey4oao0pQCY=\",\"LkcRfT+qHWTYomUreWneK2yry/xpMmPxcnRoTNtvp8E=\",\"HehQ8LbbtfijJDtvkW0eZV3SIsD018RIbob7kPVQsQs=\",\"BfvIDAEWgCIzkdTM5EJTqb2TrjX9BPSNCy67MbnCn48=\",\"HekARcIkSbfNwzLzUpMWCxNRPsi587b4gjVCxUYiflk=\",\"Ewmg/40pr1rYDyzzIlqauol+SswzZ5TVdSTz5SnfWmk=\",\"LLMGzLVXdCHGrXMca1LdTg1wsDI6ZY00MwcmiOwF4KQ=\",\"GODVGBMadOdZoJ6ypUDV0mMKcqV0UAwDmN9JmbmGi/w=\",\"CqXzBK1Ycc0K7ctzQg9x1A/s4Q6rb4QwBSZEssHBmGc=\",\"HnyavbxkomrbuPXQBjWRE4qI4dPOcJhIyd1PfVPKIxQ=\",\"KB6M8IhKV+iuWMJsAEmDreD23jR1zXtGv7wmkxXHHIY=\",\"D3+LN5RFyW0lrYZuF8dTthHcCNvSGQDIWtfU7J+r5PU=\",\"Ga3u1Cpnvdzb7wgqTUOlWZgRAiDUp9p80ZeT9LWhhq4=\",\"F9YrvUK51vd3qp+w1QXgraZcT0g6a8XcH9pOWTuKMmk=\",\"FbzTeQ9+s0b2kShF1UtNDV1dOX10CuHAcVI2bEgylL8=\",\"KXLj4Jhdr9E1fxCYpLM/DCBM4snTb6b8qxq9SWWggvY=\",\"Ar59qhVwEtlpU5k+dEqUZPo9zdBccFgUx5zsVoOTG6c=\"],[\"BCGmR8oAePZ7DJHWiGZxyj83fy8WLiodfCFfDld9Sns=\",\"JPfzZo6oNgAjlcLtuXa2jBfAJpUwv7EI1wGHQH2JwNM=\",\"IFUVnze68EwhNRCEN0vzYKh8SckfflNewhEtvIdzutc=\",\"CMb1fGawYUtIRhyIh9/ZImdmmsoOMLscLwiTQTCzb1s=\",\"LWE3ax8IKR0C6jKr5j10HnfreqDoUcSaLjihEhre4CY=\",\"HRJ+ly6nheS0b4sAcPG4DdTJlISvATV1FOn6xAXxRk8=\",\"CDJB2XTSlVNBsF55aB2Wl9Hdr6b3oDBUd8lsUFAx5e4=\",\"DTs8Nv9Ea5NhIk8omEZAlrXycADBYvlstUo9e9ihxno=\",\"Hl/qGhWMyjgt5w4ES7R33xllk1Fuj+24pOBVcEIrkk0=\",\"LjPbg4FK8nDhYBgL0PicJSWgUPDEmhIrAkm4Wng6eeM=\",\"JqXGHSe9CoHlpk3F5OZFtml8D37R/G9yiZhg70HCMfQ=\",\"IRAYwiNHdfFe4FZlFQG/tEpm2ZYOKWQUjBiwWCbqXY4=\",\"APmoAKx+ra8o5CXUA1Tx1+ghBKZKWjH+gdS/rZheIrg=\",\"HvUxp5Rfp5QmadZxFrRKKLLEsNF1y0x/0ALaQUXwCLI=\",\"CjfVChSYAtfFm0QNai/fn+L4K7/7Ictko9M/w0BJMiw=\",\"AvGQPimrWouNgceQK3lO/tvK34vWBUEqey4oao0pQCY=\",\"LkcRfT+qHWTYomUreWneK2yry/xpMmPxcnRoTNtvp8E=\",\"HehQ8LbbtfijJDtvkW0eZV3SIsD018RIbob7kPVQsQs=\",\"BfvIDAEWgCIzkdTM5EJTqb2TrjX9BPSNCy67MbnCn48=\",\"HekARcIkSbfNwzLzUpMWCxNRPsi587b4gjVCxUYiflk=\",\"Ewmg/40pr1rYDyzzIlqauol+SswzZ5TVdSTz5SnfWmk=\",\"LLMGzLVXdCHGrXMca1LdTg1wsDI6ZY00MwcmiOwF4KQ=\",\"GODVGBMadOdZoJ6ypUDV0mMKcqV0UAwDmN9JmbmGi/w=\",\"CqXzBK1Ycc0K7ctzQg9x1A/s4Q6rb4QwBSZEssHBmGc=\",\"HnyavbxkomrbuPXQBjWRE4qI4dPOcJhIyd1PfVPKIxQ=\",\"KB6M8IhKV+iuWMJsAEmDreD23jR1zXtGv7wmkxXHHIY=\",\"D3+LN5RFyW0lrYZuF8dTthHcCNvSGQDIWtfU7J+r5PU=\",\"Ga3u1Cpnvdzb7wgqTUOlWZgRAiDUp9p80ZeT9LWhhq4=\",\"F9YrvUK51vd3qp+w1QXgraZcT0g6a8XcH9pOWTuKMmk=\",\"FbzTeQ9+s0b2kShF1UtNDV1dOX10CuHAcVI2bEgylL8=\",\"KXLj4Jhdr9E1fxCYpLM/DCBM4snTb6b8qxq9SWWggvY=\",\"Ar59qhVwEtlpU5k+dEqUZPo9zdBccFgUx5zsVoOTG6c=\"]],\"MerkleProofsNftBefore\":[\"H5MB1QbSwkmPGEemLafXBd0PUEPOCfz1wn/Qe0OpOWI=\",\"FkzHIzxoZaJWkSF0KwmSNlQuofWRvMavNow8RlB4AM4=\",\"KtyOsNN9k//9F2oCd4SXxW/eXBoUn6i31Tt9jEj4cx0=\",\"BoQ4RCpJNYbw1ZRGDdIKVDzxUSgSB9iUdJhCpQDHSts=\",\"KRtF8EEMk2A99JoapAmaB3tlg8F04YVzq+dEEzXeGuQ=\",\"KiMn8PHRoFEaHWJUxYaCMnwuNolo79rGJnPt3Qr2ltA=\",\"L7njC7JReH+cF5NaUSifo2A0y87PNE5Fj8BMxHrWKwA=\",\"EzZmWz0jo/dpSZxX5cPjKxLjn3cGqCgnitKfPBn9WaM=\",\"IAZWCdz8//QeBI6skH5sxDqx42O/6na00EXPd+Jkss4=\",\"ESc0M5R50DhsG9NCFoTiiC7ywvooLJQtk0etmlgX+KU=\",\"FRnfz0ePHwdv3Ef0O024R2ov5MPlkCMSt8FJIQwA5iA=\",\"Jk3ph2K49Yz2V4BZE/D7lz2qAS0gf1DoaExg8J2GeNk=\",\"D+QSEB2GB6ixeOh0dGhnhUQBsM23NCeJth6FauKsIAE=\",\"BtvThYPRQaZ7Rs7IwQOOMrMMjzyIpi9HFyotNTfX8IY=\",\"DxQuOwiPtWyz5H4Fqg7RESb2A7Uk0ZTO7xYnhH1IJxQ=\",\"E583ss5ImtBXJekhcWX/Zo/v9D7fK6vqcGquBu4eVDI=\",\"KOyU2paogCalNtdgutJAoGoXwdds0H0uQCoCYVmxvRI=\",\"D123rLRZMQ06khbbgCdOXspqLMNfSQBPwlwJAKx/Bvc=\",\"KGPf0jjOW7rIMW52T04JSfpdDoR7zuILEOpbr0fd1jw=\",\"Ln6kP46Wcn52+ZZD9CB792gDvXQbAq2SNt95tV9Owk0=\",\"HiQocFBnKYCQeMpolOjBjz/uLw6WfBGqPL/dxmIdvCQ=\",\"IT4Us88kRcXtzCq/OQF8ho5UvfMcYH02HvJPRPK+WXU=\",\"FLpTLMHtKCFRk89veJGeyZ01UtstRLWh7LiAolqc2+E=\",\"HeparqzH20xg5TBmXZkBqGIZ+OvxaT7kWveeNX9jaqg=\",\"BnfseWBA/4QroM4CjDlStss8QJl2kIA0kkQoFIXFbpA=\",\"Joy6q1Wc5XVCVMvxuoNHtm4Xvi26u1Zh3478rh6+1NY=\",\"AouNivxTxiUQUatSu+VacKMuEUVstbpFU/h2D3E8PlE=\",\"BqBGXB4MhCDLqV2FK90+ddQ7m2CmaGEZPRJW/DGOSoM=\",\"Ey3L2XIxO+n2eYZoY6MH8a91MErhVuYmPi3uMEdnfwk=\",\"AHA1N7voZZGMWT6pxM0pwniY49w+v3b2xQZwg8GUCDg=\",\"Cj0jo978RyRM0GyKyMErhgf8knEjrMiHp6d68bgdeGE=\",\"Di6QBFfVK2JDGaxikaHkndnk1x+nHM16MUVI7L4yxW0=\",\"C7RGwM2VzB/ZO5q46stHzSSfFd1z4wFylhd0T8etbqU=\",\"AAQ6Y4nKAkYhZMkCoCUJPL3cPYCH6K+EB0cdU4f2YhQ=\",\"GDAMWBV+Ji0/PEQewYQsmAiFyFepzT0dEmy9lQ9ohfY=\",\"Ha8ctmjxS098qowF0/MceSko7q8UC5nTs6nTmnjg9Tg=\",\"EdXI0dNrlc+pxSCXiHfp6a4M8gbVWyI7kliEPSDfCyg=\",\"KL0zG1poB2RkTPLQu5QPphsfeyPI6fHEkM6rhwniOZY=\",\"EOpJg5cORJQWmLZ1aqCwwtKG+wlqjYs0S8wviBuuNDw=\",\"HRxFZvNciZPXiEvhzPZbwMJ1z+/UiAJyP0yABmfsldY=\"],\"StateRootAfter\":\"HFlK68hr3rxGII0/P3RbPHLslUV5o42z0wtcDDuekXM=\"}],\"Gas\":{\"GasAssetCount\":2,\"AccountInfoBefore\":{\"AccountIndex\":1,\"L1Address\":\"cJl5cMUYEtw6AQx9AbUODRfcecg=\",\"AccountPk\":{\"A\":{\"X\":\"8199190777948451040978801949301513350788178685232974699636521226139778292564\",\"Y\":\"17074878435405371424895458188552763456196723555144453459250457325008515674682\"}},\"Nonce\":3,\"CollectionNonce\":1,\"AssetRoot\":\"CDz5Djq/4WPV6GocQRitMFPc5ritl4AWxNBsYc7UyAA=\",\"AssetsInfo\":[{\"AssetId\":0,\"Balance\":20029990000000000,\"OfferCanceledOrFinalized\":0},{\"AssetId\":1,\"Balance\":0,\"OfferCanceledOrFinalized\":0}]},\"MerkleProofsAccountBefore\":[\"BzsoPt8d13QfT7tu+HYIoGIc9S+ClP3Sg86ANlUnd1M=\",\"FUeJdeesa/Jmd+mjTT2LjJ2926W3B8Gn360uTXXRbR8=\",\"IFUVnze68EwhNRCEN0vzYKh8SckfflNewhEtvIdzutc=\",\"CMb1fGawYUtIRhyIh9/ZImdmmsoOMLscLwiTQTCzb1s=\",\"LWE3ax8IKR0C6jKr5j10HnfreqDoUcSaLjihEhre4CY=\",\"HRJ+ly6nheS0b4sAcPG4DdTJlISvATV1FOn6xAXxRk8=\",\"CDJB2XTSlVNBsF55aB2Wl9Hdr6b3oDBUd8lsUFAx5e4=\",\"DTs8Nv9Ea5NhIk8omEZAlrXycADBYvlstUo9e9ihxno=\",\"Hl/qGhWMyjgt5w4ES7R33xllk1Fuj+24pOBVcEIrkk0=\",\"LjPbg4FK8nDhYBgL0PicJSWgUPDEmhIrAkm4Wng6eeM=\",\"JqXGHSe9CoHlpk3F5OZFtml8D37R/G9yiZhg70HCMfQ=\",\"IRAYwiNHdfFe4FZlFQG/tEpm2ZYOKWQUjBiwWCbqXY4=\",\"APmoAKx+ra8o5CXUA1Tx1+ghBKZKWjH+gdS/rZheIrg=\",\"HvUxp5Rfp5QmadZxFrRKKLLEsNF1y0x/0ALaQUXwCLI=\",\"CjfVChSYAtfFm0QNai/fn+L4K7/7Ictko9M/w0BJMiw=\",\"AvGQPimrWouNgceQK3lO/tvK34vWBUEqey4oao0pQCY=\",\"LkcRfT+qHWTYomUreWneK2yry/xpMmPxcnRoTNtvp8E=\",\"HehQ8LbbtfijJDtvkW0eZV3SIsD018RIbob7kPVQsQs=\",\"BfvIDAEWgCIzkdTM5EJTqb2TrjX9BPSNCy67MbnCn48=\",\"HekARcIkSbfNwzLzUpMWCxNRPsi587b4gjVCxUYiflk=\",\"Ewmg/40pr1rYDyzzIlqauol+SswzZ5TVdSTz5SnfWmk=\",\"LLMGzLVXdCHGrXMca1LdTg1wsDI6ZY00MwcmiOwF4KQ=\",\"GODVGBMadOdZoJ6ypUDV0mMKcqV0UAwDmN9JmbmGi/w=\",\"CqXzBK1Ycc0K7ctzQg9x1A/s4Q6rb4QwBSZEssHBmGc=\",\"HnyavbxkomrbuPXQBjWRE4qI4dPOcJhIyd1PfVPKIxQ=\",\"KB6M8IhKV+iuWMJsAEmDreD23jR1zXtGv7wmkxXHHIY=\",\"D3+LN5RFyW0lrYZuF8dTthHcCNvSGQDIWtfU7J+r5PU=\",\"Ga3u1Cpnvdzb7wgqTUOlWZgRAiDUp9p80ZeT9LWhhq4=\",\"F9YrvUK51vd3qp+w1QXgraZcT0g6a8XcH9pOWTuKMmk=\",\"FbzTeQ9+s0b2kShF1UtNDV1dOX10CuHAcVI2bEgylL8=\",\"KXLj4Jhdr9E1fxCYpLM/DCBM4snTb6b8qxq9SWWggvY=\",\"If2BsNzorNWKcMAoLIx45kf6QFnV+sZVvscO9gbRLIQ=\"],\"MerkleProofsAccountAssetsBefore\":[[\"KUIKMi/ZoykWWq/6QNECz11hcaLQI09rZlPPw7ya3T4=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"],[\"J1mnbN2UvtX8S4s7bk3pFFx9rG34LdZUyqQMNrjIiOI=\",\"AB+eRTI7DbLGXCXNxEwFNoCyvzYMPe+4bu436cU91Hg=\",\"KhWmYLyZ3iAzrY6vHKrB69l+AaB2p4/6g8VGlk15D3s=\",\"EiIgT4wAyKVniDB2mvklyLA/l2eLQvEO3J8sN3qVFLY=\",\"I9t+b0YZqKW9kOgWdiAK9TufUemL6t3mZNF4O4KhpwM=\",\"KxjbbbCpEX490YyopCukV+SiyEnmfP/XrvTSnlBHbIk=\",\"KX/pM1c8Ry8ZXVe/NtB+flPE8E/P8t4gnh7c8/Rmz6k=\",\"H3murXM0pipDr2DZVd4CvPMPEXMsh7OR52Z1RfflR7M=\",\"HkUEhuCgqCpqke/av4x4z/avwh4eZzaAsMYUd2Cz0iM=\",\"FSbDqPNMADcEV5ewR0cdsxoOUfTqqWGMog7k3dpfaw8=\",\"FgmpXO76fss1oqOoksIeBI5AsmxrnDEKyjkQ6Qt0TWc=\",\"Hx4kS6Rt3zmrBZFFrRbUB8MGRTHiwieOCnNewP3HRFE=\",\"B3ID0OW5Xtgh+RNJKzxJBPEdd/uKT1D/I7CN6wC+5IY=\",\"J1iBpjB3SZht+O9IIzbnuenoVyNsyF/GIyRJMm4f08A=\",\"LA+FoICzKzsyahbDsHb1h58aga6ABjAvGFWYUckS7pI=\",\"B+YHo88RgOcP6ADXJMoKtbgL7zYbkTO/FiSxm/JmmGw=\"]]}}"
	var cryptoBlock *circuit.Block
	err := json.Unmarshal([]byte(witnessJson), &cryptoBlock)
	if err != nil {
		t.Fatal(err)
	}
	bn, err := circuit.ChooseBN(len(cryptoBlock.Txs))
	if err != nil {
		t.Fatal(err)
	}
	blockWitness, err := circuit.SetBlockWitness(cryptoBlock, bn)
	if err != nil {
		return
	}
	witness, err := frontend.NewWitness(&blockWitness, ecc.BN254.ScalarField())
	err = oR1cs.IsSolved(witness, backend.WithHints(types.PubDataToBytes))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("block %d is solved", cryptoBlock.BlockNumber)
}

func optionalBlockSizesInt() []int {
	blockSizesStr := strings.Split(*optionalBlockSizes, ",")
	blockSizesInt := make([]int, len(blockSizesStr))
	for i := range blockSizesStr {
		v, err := strconv.Atoi(blockSizesStr[i])
		if err != nil {
			panic(err)
		}
		blockSizesInt[i] = v
	}
	return blockSizesInt
}

func chooseBN(bNFromFlag int, blockSize int) int {
	if bNFromFlag != 0 {
		return bNFromFlag
	}
	bn, err := circuit.ChooseBN(blockSize)
	if err != nil {
		panic(err)
	}
	return bn
}
