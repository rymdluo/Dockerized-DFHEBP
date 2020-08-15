package main

//import "fmt"
import "math/big"

//import "crypto/rand"
//import "encoding/hex"

import "github.com/clearmatics/bn256"

//import "golang.org/x/crypto/sha3"

// ToDO evaluate others curves such as BLS12 used by zcash, also BLS24 or others , providing ~200 bits of security , may be required for long time use( say 50 years)
type GeneratorVector struct {
	vector []*bn256.G1
}

func NewGeneratorVector(input []*bn256.G1) *GeneratorVector {
	return &GeneratorVector{vector: input}
}

func (gv *GeneratorVector) Length() int {
	return len(gv.vector)
}

// slice and return
func (gv *GeneratorVector) Slice(start, end int) *GeneratorVector {
	var result GeneratorVector
	for i := start; i < end; i++ {
		var ri bn256.G1
		ri.Set(gv.vector[i])
		result.vector = append(result.vector, &ri)
	}
	return &result
}

func (gv *GeneratorVector) Commit(exponent []*big.Int) *bn256.G1 {
	var accumulator, zero bn256.G1
	var zeroes [64]byte
	accumulator.Unmarshal(zeroes[:]) // obtain zero element, this should be static and
	zero.Unmarshal(zeroes[:])

	accumulator.ScalarMult(G, new(big.Int))

	//fmt.Printf("zero %s\n", accumulator.String())

	if len(gv.vector) != len(exponent) {
		panic("mismatched number of elements")
	}
	for i := range gv.vector { // TODO a bug exists somewhere deep here
		var tmp, accopy bn256.G1
		tmp.ScalarMult(gv.vector[i], exponent[i])

		accopy.Set(&accumulator)
		accumulator.Add(&accopy, &tmp)
	}

	return &accumulator
}

func (gv *GeneratorVector) Sum() *bn256.G1 {
	var accumulator bn256.G1

	accumulator.ScalarMult(G, new(big.Int)) // set it to zero

	for i := range gv.vector {
		var accopy bn256.G1

		accopy.Set(&accumulator)
		accumulator.Add(&accopy, gv.vector[i])
	}

	return &accumulator
}

func (gv *GeneratorVector) Add(addendum *GeneratorVector) *GeneratorVector {
	var result GeneratorVector

	if len(gv.vector) != len(addendum.vector) {
		panic("mismatched number of elements")
	}

	for i := range gv.vector {
		var ri bn256.G1

		ri.Add(gv.vector[i], addendum.vector[i])
		result.vector = append(result.vector, &ri)
	}

	return &result
}

func (gv *GeneratorVector) Hadamard(exponent []*big.Int) *GeneratorVector {
	var result GeneratorVector

	if len(gv.vector) != len(exponent) {
		panic("mismatched number of elements")
	}
	for i := range gv.vector {
		var ri bn256.G1
		ri.ScalarMult(gv.vector[i], exponent[i])
		result.vector = append(result.vector, &ri)

	}

	return &result
}

func (gv *GeneratorVector) Negate() *GeneratorVector {
	var result GeneratorVector
	for i := range gv.vector {
		var ri bn256.G1
		ri.Neg(gv.vector[i])
		result.vector = append(result.vector, &ri)
	}
	return &result
}

func (gv *GeneratorVector) Times(multiplier *big.Int) *GeneratorVector {
	var result GeneratorVector
	for i := range gv.vector {
		var ri bn256.G1
		ri.ScalarMult(gv.vector[i], multiplier)
		result.vector = append(result.vector, &ri)
	}
	return &result
}

func (gv *GeneratorVector) Extract(parity bool) *GeneratorVector {
	var result GeneratorVector

	remainder := 0
	if parity {
		remainder = 1
	}
	for i := range gv.vector {
		if i%2 == remainder {
			var ri bn256.G1
			ri.Set(gv.vector[i])
			result.vector = append(result.vector, &ri)
		}
	}
	return &result
}

func (gv *GeneratorVector) Concat(addendum *GeneratorVector) *GeneratorVector {
	var result GeneratorVector
	for i := range gv.vector {
		var ri bn256.G1
		ri.Set(gv.vector[i])
		result.vector = append(result.vector, &ri)
	}

	for i := range addendum.vector {
		var ri bn256.G1
		ri.Set(addendum.vector[i])
		result.vector = append(result.vector, &ri)
	}

	return &result
}
