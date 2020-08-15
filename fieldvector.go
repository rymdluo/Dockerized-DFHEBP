package main

//import "fmt"
import "math/big"

//import "crypto/rand"
//import "encoding/hex"

import "github.com/clearmatics/bn256"

//import "golang.org/x/crypto/sha3"

type FieldVector struct {
	vector []*big.Int
}

func NewFieldVector(input []*big.Int) *FieldVector {
	return &FieldVector{vector: input}
}

func (fv *FieldVector) Length() int {
	return len(fv.vector)
}

// slice and return
func (fv *FieldVector) Slice(start, end int) *FieldVector {
	var result FieldVector
	for i := start; i < end; i++ {
		result.vector = append(result.vector, new(big.Int).Set(fv.vector[i]))
	}
	return &result
}

//copy and return
func (fv *FieldVector) Clone() *FieldVector {
	return fv.Slice(0, len(fv.vector))
}

func (fv *FieldVector) SliceRaw(start, end int) []*big.Int {
	var result FieldVector
	for i := start; i < end; i++ {
		result.vector = append(result.vector, new(big.Int).Set(fv.vector[i]))
	}
	return result.vector
}

func (fv *FieldVector) Sum() *big.Int {
	var accumulator big.Int

	for i := range fv.vector {
		var accopy big.Int

		accopy.Add(&accumulator, fv.vector[i])
		accumulator.Mod(&accopy, bn256.Order)
	}

	return &accumulator
}

func (fv *FieldVector) Add(addendum *FieldVector) *FieldVector {
	var result FieldVector

	if len(fv.vector) != len(addendum.vector) {
		panic("mismatched number of elements")
	}

	for i := range fv.vector {
		var ri big.Int
		ri.Mod(new(big.Int).Add(fv.vector[i], addendum.vector[i]), bn256.Order)
		result.vector = append(result.vector, &ri)
	}

	return &result
}

func (gv *FieldVector) AddConstant(c *big.Int) *FieldVector {
	var result FieldVector

	for i := range gv.vector {
		var ri big.Int
		ri.Mod(new(big.Int).Add(gv.vector[i], c), bn256.Order)
		result.vector = append(result.vector, &ri)
	}

	return &result
}

func (fv *FieldVector) Hadamard(exponent *FieldVector) *FieldVector {
	var result FieldVector

	if len(fv.vector) != len(exponent.vector) {
		panic("mismatched number of elements")
	}
	for i := range fv.vector {
		result.vector = append(result.vector, new(big.Int).Mod(new(big.Int).Mul(fv.vector[i], exponent.vector[i]), bn256.Order))
	}

	return &result
}

func (fv *FieldVector) InnerProduct(exponent *FieldVector) *big.Int {
	if len(fv.vector) != len(exponent.vector) {
		panic("mismatched number of elements")
	}

	accumulator := new(big.Int)
	for i := range fv.vector {
		tmp := new(big.Int).Mod(new(big.Int).Mul(fv.vector[i], exponent.vector[i]), bn256.Order)
		accumulator.Add(accumulator, tmp)
		accumulator.Mod(accumulator, bn256.Order)
	}

	return accumulator
}

func (fv *FieldVector) Negate() *FieldVector {
	var result FieldVector
	for i := range fv.vector {
		result.vector = append(result.vector, new(big.Int).Mod(new(big.Int).Neg(fv.vector[i]), bn256.Order))
	}
	return &result
}

func (fv *FieldVector) Flip() *FieldVector {
	var result FieldVector
	for i := range fv.vector {
		result.vector = append(result.vector, new(big.Int).Set(fv.vector[(len(fv.vector)-i)%len(fv.vector)]))
	}
	return &result
}

func (fv *FieldVector) Times(multiplier *big.Int) *FieldVector {
	var result FieldVector
	for i := range fv.vector {
		res := new(big.Int).Mul(fv.vector[i], multiplier)
		res.Mod(res, bn256.Order)
		result.vector = append(result.vector, res)
	}
	return &result
}

func (fv *FieldVector) Invert() *FieldVector {
	var result FieldVector
	for i := range fv.vector {
		result.vector = append(result.vector, new(big.Int).ModInverse(fv.vector[i], bn256.Order))
	}
	return &result
}

func (fv *FieldVector) Concat(addendum *FieldVector) *FieldVector {
	var result FieldVector
	for i := range fv.vector {
		result.vector = append(result.vector, new(big.Int).Set(fv.vector[i]))
	}

	for i := range addendum.vector {
		result.vector = append(result.vector, new(big.Int).Set(addendum.vector[i]))
	}

	return &result
}

func (fv *FieldVector) Extract(parity bool) *FieldVector {
	var result FieldVector

	remainder := 0
	if parity {
		remainder = 1
	}
	for i := range fv.vector {
		if i%2 == remainder {

			result.vector = append(result.vector, new(big.Int).Set(fv.vector[i]))
		}
	}
	return &result
}

type FieldVectorPolynomial struct {
	coefficients []*FieldVector
}

func NewFieldVectorPolynomial(inputs ...*FieldVector) *FieldVectorPolynomial {
	fv := &FieldVectorPolynomial{}
	for _, input := range inputs {
		fv.coefficients = append(fv.coefficients, input.Clone())
	}
	return fv
}

func (fv *FieldVectorPolynomial) Length() int {
	return len(fv.coefficients)
}

func (fv *FieldVectorPolynomial) Evaluate(x *big.Int) *FieldVector {

	result := fv.coefficients[0].Clone()

	accumulator := new(big.Int).Set(x)

	for i := 1; i < len(fv.coefficients); i++ {
		result = result.Add(fv.coefficients[i].Times(accumulator))
		accumulator.Mul(accumulator, x)
		accumulator.Mod(accumulator, bn256.Order)

	}
	return result
}

func (fv *FieldVectorPolynomial) InnerProduct(other *FieldVectorPolynomial) []*big.Int {

	var result []*big.Int

	result_length := fv.Length() + other.Length() - 1
	for i := 0; i < result_length; i++ {
		result = append(result, new(big.Int)) // 0 value fill
	}

	for i := range fv.coefficients {
		for j := range other.coefficients {
			tmp := new(big.Int).Set(result[i+j])
			result[i+j].Add(tmp, fv.coefficients[i].InnerProduct(other.coefficients[j]))
			result[i+j].Mod(result[i+j], bn256.Order)
		}
	}
	return result
}

type PedersenCommitment struct {
	X      *big.Int
	R      *big.Int
	Params *GeneratorParams
}

func NewPedersenCommitment(params *GeneratorParams, x, r *big.Int) *PedersenCommitment {
	pc := &PedersenCommitment{Params: params, X: new(big.Int).Set(x), R: new(big.Int).Set(r)}
	return pc
}
func (pc *PedersenCommitment) Commit() *bn256.G1 {
	var left, right, result bn256.G1
	left.ScalarMult(pc.Params.G, pc.X)
	right.ScalarMult(pc.Params.H, pc.R)
	result.Add(&left, &right)
	return &result
}
func (pc *PedersenCommitment) Add(other *PedersenCommitment) *PedersenCommitment {
	var x, r big.Int
	x.Mod(new(big.Int).Add(pc.X, other.X), bn256.Order)
	r.Mod(new(big.Int).Add(pc.R, other.R), bn256.Order)
	return NewPedersenCommitment(pc.Params, &x, &r)
}
func (pc *PedersenCommitment) Times(constant *big.Int) *PedersenCommitment {
	var x, r big.Int
	x.Mod(new(big.Int).Mul(pc.X, constant), bn256.Order)
	r.Mod(new(big.Int).Mul(pc.R, constant), bn256.Order)
	return NewPedersenCommitment(pc.Params, &x, &r)
}

type PolyCommitment struct {
	coefficient_commitments []*PedersenCommitment
	Params                  *GeneratorParams
}

func NewPolyCommitment(params *GeneratorParams, coefficients []*big.Int) *PolyCommitment {
	pc := &PolyCommitment{Params: params}
	pc.coefficient_commitments = append(pc.coefficient_commitments, NewPedersenCommitment(params, coefficients[0], new(big.Int).SetUint64(0)))

	for i := 1; i < len(coefficients); i++ {
		pc.coefficient_commitments = append(pc.coefficient_commitments, NewPedersenCommitment(params, coefficients[i], RandomScalarFixed()))

	}
	return pc
}

func (pc *PolyCommitment) GetCommitments() []*bn256.G1 {
	var result []*bn256.G1
	for i := 1; i < len(pc.coefficient_commitments); i++ {
		result = append(result, pc.coefficient_commitments[i].Commit())
	}
	return result
}

func (pc *PolyCommitment) Evaluate(constant *big.Int) *PedersenCommitment {
	result := pc.coefficient_commitments[0]

	accumulator := new(big.Int).Set(constant)

	for i := 1; i < len(pc.coefficient_commitments); i++ {

		tmp := new(big.Int).Set(accumulator)
		result = result.Add(pc.coefficient_commitments[i].Times(accumulator))
		accumulator.Mod(new(big.Int).Mul(tmp, constant), bn256.Order)
	}

	return result
}

/*
// bother FieldVector and GeneratorVector satisfy this
type Vector interface{
	Length() int
	Extract(parity bool) Vector
	Add(other Vector)Vector
	Hadamard( []*big.Int) Vector
	Times (*big.Int) Vector
	Negate() Vector
}
*/

// check this https://pdfs.semanticscholar.org/d38d/e48ee4127205a0f25d61980c8f241718b66e.pdf
// https://arxiv.org/pdf/1802.03932.pdf

var unity *big.Int

func init() {
	// primitive 2^28th root of unity modulo q
	unity, _ = new(big.Int).SetString("14a3074b02521e3b1ed9852e5028452693e87be4e910500c7ba9bbddb2f46edd", 16)

}

func fft_FieldVector(input *FieldVector, inverse bool) *FieldVector {
	length := input.Length()
	if length == 1 {
		return input
	}

	// lngth must be multiple of 2 ToDO
	if length%2 != 0 {
		panic("length must be multiple of 2")
	}

	//unity,_ := new(big.Int).SetString("14a3074b02521e3b1ed9852e5028452693e87be4e910500c7ba9bbddb2f46edd",16)

	omega := new(big.Int).Exp(unity, new(big.Int).SetUint64((1<<28)/uint64(length)), bn256.Order)
	if inverse {
		omega = new(big.Int).ModInverse(omega, bn256.Order)
	}

	even := fft_FieldVector(input.Extract(false), inverse)
	odd := fft_FieldVector(input.Extract(true), inverse)

	omegas := []*big.Int{new(big.Int).SetUint64(1)}

	for i := 1; i < length/2; i++ {
		omegas = append(omegas, new(big.Int).Mod(new(big.Int).Mul(omegas[i-1], omega), bn256.Order))
	}

	omegasv := NewFieldVector(omegas)
	result := even.Add(odd.Hadamard(omegasv)).Concat(even.Add(odd.Hadamard(omegasv).Negate()))
	if inverse {
		result = result.Times(new(big.Int).ModInverse(new(big.Int).SetUint64(2), bn256.Order))
	}

	return result

}

// this is exactly same as fft_FieldVector, alternate implementation
func fftints(input []*big.Int) (result []*big.Int) {
	size := len(input)
	if size == 1 {
		return input
	}
	//require(size % 2 == 0, "Input size is not a power of 2!");

	unity, _ := new(big.Int).SetString("14a3074b02521e3b1ed9852e5028452693e87be4e910500c7ba9bbddb2f46edd", 16)

	omega := new(big.Int).Exp(unity, new(big.Int).SetUint64((1<<28)/uint64(size)), bn256.Order)

	even := fftints(extractbits(input, 0))
	odd := fftints(extractbits(input, 1))
	omega_run := new(big.Int).SetUint64(1)
	result = make([]*big.Int, len(input), len(input))
	for i := 0; i < len(input)/2; i++ {
		temp := new(big.Int).Mod(new(big.Int).Mul(odd[i], omega_run), bn256.Order)
		result[i] = new(big.Int).Mod(new(big.Int).Add(even[i], temp), bn256.Order)
		result[i+size/2] = new(big.Int).Mod(new(big.Int).Sub(even[i], temp), bn256.Order)
		omega_run = new(big.Int).Mod(new(big.Int).Mul(omega, omega_run), bn256.Order)
	}
	return result
}

func extractbits(input []*big.Int, parity int) (result []*big.Int) {
	result = make([]*big.Int, len(input)/2, len(input)/2)
	for i := 0; i < len(input)/2; i++ {
		result[i] = new(big.Int).Set(input[2*i+parity])
	}
	return
}

func fft_GeneratorVector(input *GeneratorVector, inverse bool) *GeneratorVector {
	length := input.Length()
	if length == 1 {
		return input
	}

	// lngth must be multiple of 2 ToDO
	if length%2 != 0 {
		panic("length must be multiple of 2")
	}

	// unity,_ := new(big.Int).SetString("14a3074b02521e3b1ed9852e5028452693e87be4e910500c7ba9bbddb2f46edd",16)

	omega := new(big.Int).Exp(unity, new(big.Int).SetUint64((1<<28)/uint64(length)), bn256.Order)
	if inverse {
		omega = new(big.Int).ModInverse(omega, bn256.Order)
	}

	even := fft_GeneratorVector(input.Extract(false), inverse)

	//fmt.Printf("exponent_fft %d %s \n",i, exponent_fft.vector[i].Text(16))

	odd := fft_GeneratorVector(input.Extract(true), inverse)

	omegas := []*big.Int{new(big.Int).SetUint64(1)}

	for i := 1; i < length/2; i++ {
		omegas = append(omegas, new(big.Int).Mod(new(big.Int).Mul(omegas[i-1], omega), bn256.Order))
	}

	omegasv := omegas
	result := even.Add(odd.Hadamard(omegasv)).Concat(even.Add(odd.Hadamard(omegasv).Negate()))
	if inverse {
		result = result.Times(new(big.Int).ModInverse(new(big.Int).SetUint64(2), bn256.Order))
	}

	return result

}

func Convolution(exponent *FieldVector, base *GeneratorVector) *GeneratorVector {
	size := base.Length()

	exponent_fft := fft_FieldVector(exponent.Flip(), false)

	/*exponent_fft2 := fftints( exponent.Flip().vector) // aternate implementation proof checking
	for i := range exponent_fft.vector{
				fmt.Printf("exponent_fft %d %s \n",i, exponent_fft.vector[i].Text(16))
				fmt.Printf("exponent_ff2 %d %s \n",i, exponent_fft2[i].Text(16))
			}
	*/

	temp := fft_GeneratorVector(base, false).Hadamard(exponent_fft.vector)
	return fft_GeneratorVector(temp.Slice(0, size/2).Add(temp.Slice(size/2, size)).Times(new(big.Int).ModInverse(new(big.Int).SetUint64(2), bn256.Order)), true)
	// using the optimization described here https://dsp.stackexchange.com/a/30699
}
