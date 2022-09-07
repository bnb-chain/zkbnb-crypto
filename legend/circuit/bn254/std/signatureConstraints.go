package std

const TxSignatureConstraintLimit = 32

type EcdsaSignatureConstraints struct {
	R [TxSignatureConstraintLimit]Variable
	S [TxSignatureConstraintLimit]Variable
	V Variable
}

func EmptyEcdsaSignatureConstraints() (witness EcdsaSignatureConstraints) {
	R := [32]Variable{}
	S := [32]Variable{}
	for i := range R {
		R[i] = 0
		S[i] = 0
	}
	return EcdsaSignatureConstraints{
		R: R,
		S: S,
		V: 0,
	}
}
