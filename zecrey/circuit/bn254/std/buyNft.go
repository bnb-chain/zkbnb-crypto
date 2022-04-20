package std

import (
	"errors"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"log"
)

type BuyNftProofConstraints struct {
	// commitments
	A_pk, A_TDivCRprime Point
	// response
	Z_bar_r, Z_sk, Z_skInv Variable
	// Commitment Range Proofs
	//BPrimeRangeProof      CtRangeProofConstraints
	//GasFeePrimeRangeProof CtRangeProofConstraints
	// common inputs
	C               ElGamalEncConstraints
	T, Pk           Point
	NftAccountIndex Variable
	NftIndex        Variable
	NftContentHash  Variable
	AssetId         Variable
	AssetAmount     Variable
	FeeRate         Variable
	// gas fee
	A_T_feeC_feeRPrimeInv Point
	Z_bar_r_fee           Variable
	C_fee                 ElGamalEncConstraints
	T_fee                 Point
	GasFeeAssetId         Variable
	GasFee                Variable
	C_Delta               ElGamalEncConstraints
	C_fee_DeltaForFrom    ElGamalEncConstraints
	C_fee_DeltaForGas     ElGamalEncConstraints
	IsEnabled             Variable
}

// define tests for verifying the withdraw proof
func (circuit BuyNftProofConstraints) Define(api API) error {
	// first check if C = c_1 \oplus c_2
	// get edwards curve params
	params, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	// verify H
	H := Point{
		X: HX,
		Y: HY,
	}
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	tool := NewEccTool(api, params)
	VerifyBuyNftProof(tool, api, &circuit, hFunc, H)
	return nil
}

/*
	VerifyWithdrawProof verify the withdraw proof in circuit
	@api: the constraint system
	@proof: withdraw proof circuit
	@params: params for the curve tebn254
*/
func VerifyBuyNftProof(
	tool *EccTool,
	api API,
	proof *BuyNftProofConstraints,
	hFunc MiMC,
	h Point,
) (c Variable, pkProofs [MaxRangeProofCount]CommonPkProof, tProofs [MaxRangeProofCount]CommonTProof) {
	// check params
	assetIdDiff := api.Sub(proof.GasFeeAssetId, proof.AssetId)
	checkSameAsset := api.IsZero(assetIdDiff)
	checkSameAsset = api.Select(proof.IsEnabled, checkSameAsset, 0)
	IsElGamalEncEqual(api, checkSameAsset, proof.C, proof.C_fee)
	IsPointEqual(api, checkSameAsset, proof.A_TDivCRprime, proof.A_T_feeC_feeRPrimeInv)
	deltaFeeForFrom := api.Select(checkSameAsset, proof.GasFee, ZeroInt)
	var (
		hNeg Point
	)
	hNeg = tool.Neg(h)
	deltaBalance := api.Add(proof.AssetAmount, deltaFeeForFrom)
	C_Delta := ElGamalEncConstraints{
		CL: tool.ZeroPoint(),
		CR: tool.ScalarMul(hNeg, deltaBalance),
	}
	CPrime := tool.EncAdd(proof.C, C_Delta)
	CPrimeNeg := tool.NegElgamal(CPrime)
	C_fee_DeltaForGas := ElGamalEncConstraints{
		CL: tool.ZeroPoint(),
		CR: tool.ScalarMul(h, proof.GasFee),
	}
	C_fee_DeltaForFrom := ElGamalEncConstraints{
		CL: tool.ZeroPoint(),
		CR: tool.Neg(C_fee_DeltaForGas.CR),
	}
	C_fee_DeltaForFrom = SelectElgamal(api, checkSameAsset, C_Delta, C_fee_DeltaForFrom)
	C_feePrime := tool.EncAdd(proof.C_fee, C_fee_DeltaForFrom)
	C_feePrimeNeg := tool.NegElgamal(C_feePrime)
	hFunc.Write(FixedCurveParam(api))
	WriteEncIntoBuf(&hFunc, proof.C_fee)
	hFunc.Write(proof.GasFeeAssetId)
	hFunc.Write(proof.GasFee)
	hFunc.Write(proof.NftAccountIndex)
	hFunc.Write(proof.NftIndex)
	hFunc.Write(proof.NftContentHash)
	hFunc.Write(proof.AssetId)
	hFunc.Write(proof.AssetAmount)
	hFunc.Write(proof.FeeRate)
	// gas fee
	WriteEncIntoBuf(&hFunc, proof.C)
	WritePointIntoBuf(&hFunc, proof.T)
	WritePointIntoBuf(&hFunc, proof.T_fee)
	WritePointIntoBuf(&hFunc, proof.Pk)
	WritePointIntoBuf(&hFunc, proof.A_pk)
	WritePointIntoBuf(&hFunc, proof.A_TDivCRprime)
	WritePointIntoBuf(&hFunc, proof.A_T_feeC_feeRPrimeInv)
	c = hFunc.Sum()
	// Verify balance
	//var l1, r1 Point
	//// verify pk = g^{sk}
	//l1.ScalarMulFixedBase(api, params.BaseX, params.BaseY, proof.Z_sk, params)
	//r1.ScalarMulNonFixedBase(api, &proof.Pk, c, params)
	//r1.AddGeneric(api, &proof.A_pk, &r1, params)
	//IsPointEqual(api, proof.IsEnabled, l1, r1)

	//var l2, r2 Point
	// verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	//l2 = tool.Add(tool.ScalarBaseMul(proof.Z_bar_r), tool.ScalarMul(CPrimeNeg.CL, proof.Z_skInv))
	//r2 = tool.Add(proof.A_TDivCRprime, tool.ScalarMul(tool.Add(proof.T, CPrimeNeg.CR), c))
	//IsPointEqual(api, proof.IsEnabled, l2, r2)
	// Verify T(C_R - C_R^{\star})^{-1} = (C_L - C_L^{\star})^{-sk^{-1}} g^{\bar{r}}
	//l1 := tool.Add(tool.ScalarBaseMul(proof.Z_bar_r_fee), tool.ScalarMul(C_feePrimeNeg.CL, proof.Z_skInv))
	//r1 := tool.Add(proof.A_T_feeC_feeRPrimeInv, tool.ScalarMul(tool.Add(proof.T_fee, C_feePrimeNeg.CR), c))
	//IsPointEqual(api, proof.IsEnabled, l1, r1)
	// set common parts
	pkProofs[0] = SetPkProof(proof.Pk, proof.A_pk, proof.Z_sk, proof.Z_skInv)
	for i := 1; i < MaxRangeProofCount; i++ {
		pkProofs[i] = pkProofs[0]
	}
	tProofs[0] = SetTProof(CPrimeNeg, proof.A_TDivCRprime, proof.Z_bar_r, proof.T)
	tProofs[1] = SetTProof(C_feePrimeNeg, proof.A_T_feeC_feeRPrimeInv, proof.Z_bar_r_fee, proof.T_fee)
	for i := 2; i < MaxRangeProofCount; i++ {
		tProofs[i] = tProofs[0]
	}
	// set proof deltas
	proof.C_Delta = C_Delta
	proof.C_fee_DeltaForGas = C_fee_DeltaForGas
	proof.C_fee_DeltaForFrom = C_fee_DeltaForFrom
	return c, pkProofs, tProofs
}

func SetEmptyBuyNftProofWitness() (witness BuyNftProofConstraints) {
	// commitments
	witness.A_pk, _ = SetPointWitness(BasePoint)
	witness.A_TDivCRprime, _ = SetPointWitness(BasePoint)
	// response
	witness.Z_bar_r = ZeroInt
	witness.Z_sk = ZeroInt
	witness.Z_skInv = ZeroInt
	// common inputs
	witness.C, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.T, _ = SetPointWitness(BasePoint)
	witness.Pk, _ = SetPointWitness(BasePoint)
	witness.NftAccountIndex = ZeroInt
	witness.NftIndex = ZeroInt
	witness.NftContentHash = ZeroInt
	witness.AssetId = ZeroInt
	witness.AssetAmount = ZeroInt
	witness.FeeRate = ZeroInt
	// gas fee
	witness.A_T_feeC_feeRPrimeInv, _ = SetPointWitness(BasePoint)
	witness.Z_bar_r_fee = ZeroInt
	witness.C_fee, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.T_fee, _ = SetPointWitness(BasePoint)
	witness.GasFeeAssetId = ZeroInt
	witness.GasFee = ZeroInt
	witness.C_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_fee_DeltaForFrom, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_fee_DeltaForGas, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.IsEnabled = SetBoolWitness(false)
	return witness
}

// set the witness for withdraw proof
func SetBuyNftProofWitness(proof *zecrey.BuyNftProof, isEnabled bool) (witness BuyNftProofConstraints, err error) {
	if proof == nil {
		log.Println("[SetBuyNftProofWitness] invalid params")
		return witness, err
	}

	// proof must be correct
	verifyRes, err := proof.Verify()
	if err != nil {
		log.Println("[SetBuyNftProofWitness] invalid proof:", err)
		return witness, err
	}
	if !verifyRes {
		log.Println("[SetBuyNftProofWitness] invalid proof")
		return witness, errors.New("[SetBuyNftProofWitness] invalid proof")
	}
	// commitments
	witness.A_pk, err = SetPointWitness(proof.A_pk)
	if err != nil {
		return witness, err
	}
	witness.A_TDivCRprime, err = SetPointWitness(proof.A_TDivCRprime)
	if err != nil {
		return witness, err
	}
	// response
	witness.Z_bar_r = proof.Z_bar_r
	witness.Z_sk = proof.Z_sk
	witness.Z_skInv = proof.Z_skInv
	// common inputs
	witness.C, err = SetElGamalEncWitness(proof.C)
	if err != nil {
		return witness, err
	}
	witness.T, err = SetPointWitness(proof.T)
	if err != nil {
		return witness, err
	}
	witness.Pk, err = SetPointWitness(proof.Pk)
	if err != nil {
		return witness, err
	}
	witness.NftAccountIndex = proof.NftAccountIndex
	witness.NftIndex = proof.NftIndex
	witness.NftContentHash = proof.NftContentHash
	witness.AssetId = uint64(proof.AssetId)
	witness.AssetAmount = proof.AssetAmount
	witness.FeeRate = proof.FeeRate
	// gas fee
	witness.A_T_feeC_feeRPrimeInv, err = SetPointWitness(proof.A_T_feeC_feeRPrimeInv)
	if err != nil {
		return witness, err
	}
	witness.Z_bar_r_fee = proof.Z_bar_r_fee
	witness.C_fee, err = SetElGamalEncWitness(proof.C_fee)
	if err != nil {
		return witness, err
	}
	witness.T_fee, err = SetPointWitness(proof.T_fee)
	if err != nil {
		return witness, err
	}
	witness.GasFeeAssetId = uint64(proof.GasFeeAssetId)
	witness.GasFee = proof.GasFee
	//witness.BPrimeRangeProof, err = SetCtRangeProofWitness(proof.BPrimeRangeProof, isEnabled)
	//if err != nil {
	//	return witness, err
	//}
	// common inputs
	witness.C_Delta, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_fee_DeltaForFrom, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.C_fee_DeltaForGas, _ = SetElGamalEncWitness(ZeroElgamalEnc)
	witness.IsEnabled = SetBoolWitness(isEnabled)
	return witness, nil
}

/*
	VerifyBuyNftTxParams:
	accounts order is:
	- BuyerAccount
		- Assets
			- AssetA
			- AssetGas
		- Nft
			- empty
	- OwnerAccount
		- Nft
			- nft index
	- TreasuryAccount
		- Assets
			- AssetA
	- GasAccount
		- Assets
			- AssetGas
*/
func VerifyBuyNftTxParams(api API, flag Variable, nilHash Variable, tx BuyNftProofConstraints, accountsBefore, accountsAfter [NbAccountsPerTx]AccountConstraints) {
	// verify params
	// nft index
	IsVariableEqual(api, flag, tx.NftIndex, accountsBefore[0].NftInfo.NftIndex)
	IsVariableEqual(api, flag, tx.NftIndex, accountsBefore[1].NftInfo.NftIndex)
	IsVariableEqual(api, flag, tx.NftIndex, accountsAfter[0].NftInfo.NftIndex)
	// buyer nft should be empty
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.NftContentHash, nilHash)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetId, DefaultInt)
	IsVariableEqual(api, flag, accountsBefore[0].NftInfo.AssetAmount, DefaultInt)
	// owner nft asset id and amount
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[1].NftInfo.AssetId)
	IsVariableEqual(api, flag, tx.AssetAmount, accountsBefore[1].NftInfo.AssetAmount)
	// treasury asset id
	IsVariableEqual(api, flag, tx.AssetId, accountsBefore[2].AssetsInfo[0].AssetId)
	IsVariableEqual(api, flag, tx.GasFeeAssetId, accountsBefore[3].AssetsInfo[0].AssetId)
}
