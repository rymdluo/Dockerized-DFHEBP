package main

import "fmt"
import "math"
import "math/big"

//import "crypto/rand"
//import "encoding/hex"

import "github.com/clearmatics/bn256"

//import "golang.org/x/crypto/sha3"

import "github.com/kubernetes/klog"

type Proof struct {
	BA *bn256.G1
	BS *bn256.G1
	A  *bn256.G1
	B  *bn256.G1

	CLnG, CRnG, C_0G, DG, y_0G, gG, C_XG, y_XG []*bn256.G1

	u *bn256.G1

	f *FieldVector

	z_A *big.Int

	tCommits *GeneratorVector

	that *big.Int
	mu   *big.Int

	c                     *big.Int
	s_sk, s_r, s_b, s_tau *big.Int

	ip *InnerProduct
}

type IPStatement struct {
	PrimeBase *GeneratorParams
	P         *bn256.G1
}

type IPWitness struct {
	L *FieldVector
	R *FieldVector
}

func (p *Proof) Size() int {
	size := 4*POINT_SIZE + (len(p.CLnG)+len(p.CRnG)+len(p.C_0G)+len(p.DG)+len(p.y_0G)+len(p.gG)+len(p.C_XG)+len(p.y_XG))*POINT_SIZE
	size += POINT_SIZE
	size += len(p.f.vector) * FIELDELEMENT_SIZE
	size += FIELDELEMENT_SIZE
	size += len(p.tCommits.vector) * POINT_SIZE
	size += 7 * FIELDELEMENT_SIZE
	size += p.ip.Size()
	return size
}

func (proof *Proof) hashmash1(v *big.Int) *big.Int {
	var input []byte
	input = append(input, convertbiginttobyte(v)...)
	for i := range proof.CLnG {
		input = append(input, proof.CLnG[i].Marshal()...)
	}
	for i := range proof.CRnG {
		input = append(input, proof.CRnG[i].Marshal()...)
	}
	for i := range proof.C_0G {
		input = append(input, proof.C_0G[i].Marshal()...)
	}
	for i := range proof.DG {
		input = append(input, proof.DG[i].Marshal()...)
	}
	for i := range proof.y_0G {
		input = append(input, proof.y_0G[i].Marshal()...)
	}
	for i := range proof.gG {
		input = append(input, proof.gG[i].Marshal()...)
	}
	for i := range proof.C_XG {
		input = append(input, proof.C_XG[i].Marshal()...)
	}
	for i := range proof.y_XG {
		input = append(input, proof.y_XG[i].Marshal()...)
	}
	return reducedhash(input)
}

// function, which takes a string as
// argument and return the reverse of string.
func reverse(s string) string {
	rns := []rune(s) // convert to rune
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {

		// swap the letters of the string,
		// like first with last and so on.
		rns[i], rns[j] = rns[j], rns[i]
	}

	// return the reversed string.
	return string(rns)
}

func GenerateProof(s *Statement, witness *Witness, u *bn256.G1) *Proof {

	var proof Proof
	proof.u = u
	params := NewGeneratorParams(128) // these can be pregenerated similarly as in DERO project
	statementhash := s.Hash()

	btransfer := new(big.Int).SetInt64(int64(witness.TransferAmount)) // this should be reduced
	bdiff := new(big.Int).SetInt64(int64(witness.Balance))            // this should be reduced

	number := btransfer.Add(btransfer, bdiff.Lsh(bdiff, 64)) // we are placing balance and left over balance, and doing a range proof of 128 bits

	number_string := reverse("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" + number.Text(2))
	number_string_left_128bits := string(number_string[0:128])

	var aLa, aRa []*big.Int // convert the amount to make sure it cannot be negative

	klog.V(2).Infof("reverse %s\n", number_string_left_128bits)
	for _, b := range []byte(number_string_left_128bits) {
		var l, r big.Int
		if b == '1' {
			l.SetInt64(1)
		} else {
			r.Mod(new(big.Int).SetInt64(-1), bn256.Order)
		}
		aLa = append(aLa, &l)
		aRa = append(aRa, &r)
	}

	//klog.V(2).Infof("aRa %+v\n", aRa)

	aL := NewFieldVector(aLa)
	aR := NewFieldVector(aRa)

	alpha := RandomScalar()
	klog.V(2).Infof("alpha %s\n", alpha.Text(16))

	proof.BA = params.Commit(alpha, aL, aR)

	var sLa, sRa []*big.Int
	for i := 0; i < len(aLa); i++ {
		sLa = append(sLa, RandomScalarFixed())
	}
	for i := 0; i < len(aRa); i++ {
		sRa = append(sRa, RandomScalarFixed())
	}
	sL := NewFieldVector(sLa)
	sR := NewFieldVector(sRa)
	rho := RandomScalarFixed()

	proof.BS = params.Commit(rho, sL, sR)

	klog.V(2).Infof("Proof BA %s\n", proof.BA.String())
	klog.V(2).Infof("Proof BS %s\n", proof.BS.String())

	if len(s.Publickeylist) >= 1 && len(s.Publickeylist)&(len(s.Publickeylist)-1) != 0 {
		panic("we need power of 2")
	}

	N := len(s.Publickeylist)
	m := int(math.Log2(float64(N)))

	if math.Pow(2, float64(m)) != float64(N) {
		panic("log failed")
	}

	r_A := RandomScalarFixed()
	r_B := RandomScalarFixed()
	var aa, ba, bspecial []*big.Int
	for i := 0; i < 2*m; i++ {
		aa = append(aa, RandomScalarFixed())
	}

	witness_index := reverse(fmt.Sprintf("%0"+fmt.Sprintf("%db", m)+"%0"+fmt.Sprintf("%db", m), witness.index[1], witness.index[0]))

	for _, b := range []byte(witness_index) {
		var q, bs big.Int
		if b == '1' {
			q.SetInt64(1)
			bs.Mod(new(big.Int).SetInt64(-1), bn256.Order)
		} else {
			bs.SetInt64(1)
		}
		ba = append(ba, &q)
		bspecial = append(bspecial, &bs)

	}

	a := NewFieldVector(aa)
	b := NewFieldVector(ba)

	klog.V(1).Infof("witness_index of sender/receiver %s\n", witness_index)

	c := a.Hadamard(NewFieldVector(bspecial))
	d := a.Hadamard(a).Negate()

	klog.V(2).Infof("d %s\n", d.vector[0].Text(16))

	e := NewFieldVector([]*big.Int{new(big.Int).Mod(new(big.Int).Mul(a.vector[0], a.vector[m]), bn256.Order),
		new(big.Int).Mod(new(big.Int).Mul(a.vector[0], a.vector[m]), bn256.Order)})

	second := new(big.Int).Set(a.vector[b.vector[m].Uint64()*uint64(m)])
	second.Neg(second)

	proof.f = NewFieldVector([]*big.Int{a.vector[b.vector[0].Uint64()*uint64(m)], new(big.Int).Mod(second, bn256.Order)})

	for i := range proof.f.vector {
		klog.V(2).Infof("proof.f %d %s\n", i, proof.f.vector[i].Text(16))
	}

	proof.A = params.Commit(r_A, a.Concat(d).Concat(e), nil)
	proof.B = params.Commit(r_B, b.Concat(c).Concat(proof.f), nil)

	klog.V(2).Infof("Proof A %s\n", proof.A.String())
	klog.V(2).Infof("Proof B %s\n", proof.B.String())

	var v *big.Int

	{ // hash mash
		var input []byte
		input = append(input, convertbiginttobyte(statementhash)...)
		input = append(input, proof.BA.Marshal()...)
		input = append(input, proof.BS.Marshal()...)
		input = append(input, proof.A.Marshal()...)
		input = append(input, proof.B.Marshal()...)
		v = reducedhash(input)
	}

	var phi, chi, psi, omega FieldVector
	for i := 0; i < m; i++ {
		phi.vector = append(phi.vector, RandomScalarFixed())
		chi.vector = append(chi.vector, RandomScalarFixed())
		psi.vector = append(psi.vector, RandomScalarFixed())
		omega.vector = append(omega.vector, RandomScalarFixed())

	}

	var P, Q, Pi, Qi [][]*big.Int
	Pi = RecursivePolynomials(Pi, NewPolynomial(nil), a.SliceRaw(0, m), b.SliceRaw(0, m))
	Qi = RecursivePolynomials(Qi, NewPolynomial(nil), a.SliceRaw(m, 2*m), b.SliceRaw(m, 2*m))

	// transpose the matrices
	for i := 0; i < m; i++ {
		P = append(P, []*big.Int{})
		Q = append(Q, []*big.Int{})
		for j := range Pi {
			P[i] = append(P[i], Pi[j][i])
			Q[i] = append(Q[i], Qi[j][i])
		}
	}

	for i := range P {
		for j := range P[i] {
			klog.V(2).Infof("P%d,%d %s\n", i, j, P[i][j].Text(16))
		}
	}

	for i := 0; i < m; i++ {

		{ // CLnG
			var rightp, result bn256.G1
			leftp := NewGeneratorVector(s.CLn).Commit(P[i])
			rightp.ScalarMult(s.Publickeylist[witness.index[0]], phi.vector[i])
			result.Add(leftp, &rightp)
			proof.CLnG = append(proof.CLnG, &result)
			//klog.V(2).Infof("CLnG %d %s\n",i, result.String())
		}

		{ // CRnG
			var rightp, result bn256.G1
			leftp := NewGeneratorVector(s.CRn).Commit(P[i])
			rightp.ScalarMult(params.G, phi.vector[i])
			result.Add(leftp, &rightp)
			proof.CRnG = append(proof.CRnG, &result)
			//klog.V(2).Infof("CRnG %d %s\n",i, result.String())
		}

		{ // C_0G
			var rightp, result bn256.G1
			leftp := NewGeneratorVector(s.C).Commit(P[i])
			rightp.ScalarMult(s.Publickeylist[witness.index[0]], chi.vector[i])
			result.Add(leftp, &rightp)
			proof.C_0G = append(proof.C_0G, &result)
		}

		{ // DG
			var result bn256.G1
			result.ScalarMult(params.G, chi.vector[i])
			proof.DG = append(proof.DG, &result)
			//klog.V(2).Infof("DG %d %s\n",i, result.String())
		}

		{ // y_0G
			var rightp, result bn256.G1
			leftp := NewGeneratorVector(s.Publickeylist).Commit(P[i])
			rightp.ScalarMult(s.Publickeylist[witness.index[0]], psi.vector[i])
			result.Add(leftp, &rightp)
			proof.y_0G = append(proof.y_0G, &result)
			//klog.V(2).Infof("y_0G %d %s\n",i, result.String())
		}

		{ // gG
			var result bn256.G1
			result.ScalarMult(params.G, psi.vector[i])
			proof.gG = append(proof.gG, &result)
			//klog.V(2).Infof("gG %d %s\n",i, result.String())
		}

		{ // C_XG
			var result bn256.G1
			result.ScalarMult(s.D, omega.vector[i])
			proof.C_XG = append(proof.C_XG, &result)
			//klog.V(2).Infof("C_XG %d %s\n",i, result.String())
		}

		{ // y_XG
			var result bn256.G1
			result.ScalarMult(params.G, omega.vector[i])
			proof.y_XG = append(proof.y_XG, &result)
			klog.V(2).Infof("y_XG %d %s\n", i, result.String())
		}

	}

	for i := range proof.CLnG {
		klog.V(2).Infof("CLnG %d %s\n", i, proof.CLnG[i].String())
	}
	for i := range proof.CRnG {
		klog.V(2).Infof("CRnG %d %s\n", i, proof.CRnG[i].String())
	}
	for i := range proof.C_0G {
		klog.V(2).Infof("C_0G %d %s\n", i, proof.C_0G[i].String())
	}
	for i := range proof.DG {
		klog.V(2).Infof("DG %d %s\n", i, proof.DG[i].String())
	}
	for i := range proof.y_0G {
		klog.V(2).Infof("y_0G %d %s\n", i, proof.y_0G[i].String())
	}
	for i := range proof.gG {
		klog.V(2).Infof("gG %d %s\n", i, proof.gG[i].String())
	}
	for i := range proof.C_XG {
		klog.V(2).Infof("C_XG %d %s\n", i, proof.C_XG[i].String())
	}
	for i := range proof.y_XG {
		klog.V(2).Infof("y_XG %d %s\n", i, proof.y_XG[i].String())
	}

	vPow := new(big.Int).SetInt64(1) // doesn't need reduction, since it' alredy reduced

	for i := 0; i < N; i++ {
		var temp bn256.G1
		temp.ScalarMult(params.G, new(big.Int).Mod(new(big.Int).Mul(new(big.Int).SetUint64(uint64(witness.TransferAmount)), vPow), bn256.Order))

		var poly [][]*big.Int
		if i%2 == 0 {
			poly = P
		} else {
			poly = Q
		}

		klog.V(2).Infof("\n\n")
		for i := range proof.C_XG {
			klog.V(2).Infof("C_XG before %d %s\n", i, proof.C_XG[i].String())
		}

		for j := range proof.C_XG {
			var copy1, tmpmul bn256.G1
			copy1.Set(proof.C_XG[j])
			part1 := new(big.Int).Mod(poly[j][(witness.index[0]+N-(i-i%2))%N], bn256.Order)
			part1 = new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mod(part1.Neg(part1), bn256.Order), poly[j][(witness.index[1]+N-(i-i%2))%N]), bn256.Order)

			tmpmul.ScalarMult(&temp, part1)

			proof.C_XG[j].Add(&copy1, &tmpmul)

		}

		if i != 0 {
			vPow.Mul(vPow, v)
			vPow.Mod(vPow, bn256.Order)
		}

		//klog.V(2).Infof("vPow %d %s\n", i, vPow.Text(16)))

	}

	klog.V(2).Infof("\n\n")
	for i := range proof.C_XG {
		klog.V(2).Infof("C_XG after %d %s\n", i, proof.C_XG[i].String())
	}

	// for  i:= range C_XG {
	//	klog.V(2).Infof("C_XG %d %s\n", i, C_XG[i].String())
	//}

	// calculate w hashmash

	w := proof.hashmash1(v)

	{
		var input []byte

		input = append(input, convertbiginttobyte(v)...)
		for i := range proof.CLnG {
			input = append(input, proof.CLnG[i].Marshal()...)
		}
		for i := range proof.CRnG {
			input = append(input, proof.CRnG[i].Marshal()...)
		}

		for i := range proof.C_0G {
			input = append(input, proof.C_0G[i].Marshal()...)
		}
		for i := range proof.DG {
			input = append(input, proof.DG[i].Marshal()...)
		}
		for i := range proof.y_0G {
			input = append(input, proof.y_0G[i].Marshal()...)
		}
		for i := range proof.gG {
			input = append(input, proof.gG[i].Marshal()...)
		}
		for i := range proof.C_XG {
			input = append(input, proof.C_XG[i].Marshal()...)
		}
		for i := range proof.y_XG {
			input = append(input, proof.y_XG[i].Marshal()...)
		}
		klog.V(2).Infof("whash     %s  %s\n", reducedhash(input).Text(16), w.Text(16))

	}

	proof.f = b.Times(w).Add(a)

	for i := range proof.f.vector {
		klog.V(2).Infof("proof.f %d %s\n", i, proof.f.vector[i].Text(16))
	}

	ttttt := new(big.Int).Mod(new(big.Int).Mul(r_B, w), bn256.Order)
	proof.z_A = new(big.Int).Mod(new(big.Int).Add(ttttt, r_A), bn256.Order)

	klog.V(2).Infof("proofz_A  %s\n", proof.z_A.Text(16))

	y := reducedhash(convertbiginttobyte(w))

	klog.V(2).Infof("yyyyyyyyyy  %s\n", y.Text(16))

	ys_raw := []*big.Int{new(big.Int).SetUint64(1)}
	for i := 1; i < 128; i++ {
		var tt big.Int
		tt.Mul(ys_raw[len(ys_raw)-1], y)
		tt.Mod(&tt, bn256.Order)
		ys_raw = append(ys_raw, &tt)
	}
	ys := NewFieldVector(ys_raw)

	z := reducedhash(convertbiginttobyte(y))
	klog.V(2).Infof("zzzzzzzzzz  %s %s\n", z.Text(16))

	zs := []*big.Int{new(big.Int).Exp(z, new(big.Int).SetUint64(2), bn256.Order), new(big.Int).Exp(z, new(big.Int).SetUint64(3), bn256.Order)}
	for i := range zs {
		klog.V(2).Infof("zs %d %s\n", i, zs[i].Text(16))
	}

	twos := []*big.Int{new(big.Int).SetUint64(1)}
	for i := 1; i < 64; i++ {
		var tt big.Int
		tt.Mul(twos[len(twos)-1], new(big.Int).SetUint64(2))
		tt.Mod(&tt, bn256.Order)
		twos = append(twos, &tt)
	}

	twoTimesZs := []*big.Int{}
	for i := 0; i < 2; i++ {
		for j := 0; j < 64; j++ {
			var tt big.Int
			tt.Mul(zs[i], twos[j])
			tt.Mod(&tt, bn256.Order)
			twoTimesZs = append(twoTimesZs, &tt)

			klog.V(2).Infof("twoTimesZssss ============= %d %s\n", i*32+j, twoTimesZs[i*32+j].Text(16))

		}
	}

	tmp := aL.AddConstant(new(big.Int).Mod(new(big.Int).Neg(z), bn256.Order))
	lPoly := NewFieldVectorPolynomial(tmp, sL)
	for i := range lPoly.coefficients {
		for j := range lPoly.coefficients[i].vector {
			//klog.V(2).Infof("tmp %d,%d %s\n", i,j, tmp.vector[j].Text(16))

			klog.V(2).Infof("lPoly %d,%d %s\n", i, j, lPoly.coefficients[i].vector[j].Text(16))
		}
	}

	rPoly := NewFieldVectorPolynomial(ys.Hadamard(aR.AddConstant(z)).Add(NewFieldVector(twoTimesZs)), sR.Hadamard(ys))
	for i := range rPoly.coefficients {
		for j := range rPoly.coefficients[i].vector {
			//klog.V(2).Infof("tmp %d,%d %s\n", i,j, tmp.vector[j].Text(16))

			klog.V(2).Infof("rPoly %d,%d %s\n", i, j, rPoly.coefficients[i].vector[j].Text(16))
		}
	}

	tPolyCoefficients := lPoly.InnerProduct(rPoly) // just an array of BN Reds... should be length 3
	for j := range tPolyCoefficients {
		klog.V(2).Infof("tPolyCoefficients %d,%d %s\n", 0, j, tPolyCoefficients[j].Text(16))
	}

	polyCommitment := NewPolyCommitment(params, tPolyCoefficients)
	proof.tCommits = NewGeneratorVector(polyCommitment.GetCommitments())

	for j := range proof.tCommits.vector {
		klog.V(2).Infof("tCommits %d %s\n", j, proof.tCommits.vector[j].String())
	}

	x := new(big.Int)

	{
		var input []byte
		input = append(input, convertbiginttobyte(z)...) // tie intermediates/commit
		for j := range proof.tCommits.vector {
			input = append(input, proof.tCommits.vector[j].Marshal()...)
		}
		x = reducedhash(input)
	}

	klog.V(2).Infof("x  %s\n", x.Text(16))

	evalCommit := polyCommitment.Evaluate(x)

	//klog.V(2).Infof("evalCommit.X  %s\n", j, evalCommit.X.Text(16))
	//klog.V(2).Infof("evalCommit.R  %s\n", j, evalCommit.R.Text(16))

	proof.that = evalCommit.X

	klog.V(2).Infof("evalCommit.that  %s\n", proof.that.Text(16))

	tauX := evalCommit.R

	proof.mu = new(big.Int).Mod(new(big.Int).Mul(rho, x), bn256.Order)
	proof.mu.Add(proof.mu, alpha)
	proof.mu.Mod(proof.mu, bn256.Order)

	klog.V(2).Infof("proof.mu  %s\n", proof.mu.Text(16))

	var CrnR, y_0R, y_XR, DR, gR bn256.G1
	CrnR.ScalarMult(params.G, new(big.Int))
	y_0R.ScalarMult(params.G, new(big.Int))
	y_XR.ScalarMult(params.G, new(big.Int))
	DR.ScalarMult(params.G, new(big.Int))
	gR.ScalarMult(params.G, new(big.Int))

	var p_, q_ []*big.Int
	for i := 0; i < N; i++ {
		p_ = append(p_, new(big.Int))
		q_ = append(q_, new(big.Int))
	}
	p := NewFieldVector(p_)
	q := NewFieldVector(q_)

	wPow := new(big.Int).SetUint64(1) // already reduced

	for i := 0; i < m; i++ {

		{
			tmp := new(bn256.G1)
			mm := new(big.Int).Mod(new(big.Int).Neg(phi.vector[i]), bn256.Order)
			mm = mm.Mod(new(big.Int).Mul(mm, wPow), bn256.Order)
			tmp.ScalarMult(params.G, mm)
			CrnR.Add(new(bn256.G1).Set(&CrnR), tmp)
		}

		{
			tmp := new(bn256.G1)
			mm := new(big.Int).Mod(new(big.Int).Neg(chi.vector[i]), bn256.Order)
			mm = mm.Mod(new(big.Int).Mul(mm, wPow), bn256.Order)
			tmp.ScalarMult(params.G, mm)
			DR.Add(new(bn256.G1).Set(&DR), tmp)
		}

		{
			tmp := new(bn256.G1)
			mm := new(big.Int).Mod(new(big.Int).Neg(psi.vector[i]), bn256.Order)
			mm = mm.Mod(new(big.Int).Mul(mm, wPow), bn256.Order)
			tmp.ScalarMult(s.Publickeylist[witness.index[0]], mm)
			y_0R.Add(new(bn256.G1).Set(&y_0R), tmp)
		}

		{
			tmp := new(bn256.G1)
			mm := new(big.Int).Mod(new(big.Int).Neg(psi.vector[i]), bn256.Order)
			mm = mm.Mod(new(big.Int).Mul(mm, wPow), bn256.Order)
			tmp.ScalarMult(params.G, mm)
			gR.Add(new(bn256.G1).Set(&gR), tmp)
		}

		{
			tmp := new(bn256.G1)
			tmp.ScalarMult(proof.y_XG[i], new(big.Int).Neg(wPow))
			y_XR.Add(new(bn256.G1).Set(&y_XR), tmp)
		}

		p = p.Add(NewFieldVector(P[i]).Times(wPow))
		q = q.Add(NewFieldVector(Q[i]).Times(wPow))
		wPow = new(big.Int).Mod(new(big.Int).Mul(wPow, w), bn256.Order)

		klog.V(2).Infof("wPow %s\n", wPow.Text(16))

	}

	CrnR.Add(new(bn256.G1).Set(&CrnR), new(bn256.G1).ScalarMult(s.CRn[witness.index[0]], wPow))
	y_0R.Add(new(bn256.G1).Set(&y_0R), new(bn256.G1).ScalarMult(s.Publickeylist[witness.index[0]], wPow))
	DR.Add(new(bn256.G1).Set(&DR), new(bn256.G1).ScalarMult(s.D, wPow))
	gR.Add(new(bn256.G1).Set(&gR), new(bn256.G1).ScalarMult(params.G, wPow))

	var p__, q__ []*big.Int
	for i := 0; i < N; i++ {

		if i == witness.index[0] {
			p__ = append(p__, new(big.Int).Set(wPow))
		} else {
			p__ = append(p__, new(big.Int))
		}

		if i == witness.index[1] {
			q__ = append(q__, new(big.Int).Set(wPow))
		} else {
			q__ = append(q__, new(big.Int))
		}
	}
	p = p.Add(NewFieldVector(p__))
	q = q.Add(NewFieldVector(q__))

	klog.V(2).Infof("CrnR %s\n", CrnR.String())
	klog.V(2).Infof("DR %s\n", DR.String())
	klog.V(2).Infof("y_0R %s\n", y_0R.String())
	klog.V(2).Infof("gR %s\n", gR.String())
	klog.V(2).Infof("y_XR %s\n", y_XR.String())

	for i := range p.vector {
		klog.V(2).Infof("p %d %s \n", i, p.vector[i].Text(16))
	}

	for i := range q.vector {
		klog.V(2).Infof("q %d %s \n", i, q.vector[i].Text(16))
	}

	y_p := Convolution(p, NewGeneratorVector(s.Publickeylist))
	y_q := Convolution(q, NewGeneratorVector(s.Publickeylist))

	for i := range y_p.vector {
		klog.V(2).Infof("y_p %d %s \n", i, y_p.vector[i].String())
	}
	for i := range y_q.vector {
		klog.V(2).Infof("y_q %d %s \n", i, y_q.vector[i].String())
	}

	vPow = new(big.Int).SetUint64(1) // already reduced
	for i := 0; i < N; i++ {

		ypoly := y_p
		if i%2 == 1 {
			ypoly = y_q
		}
		y_XR.Add(new(bn256.G1).Set(&y_XR), new(bn256.G1).ScalarMult(ypoly.vector[i/2], vPow))
		if i > 0 {
			vPow = new(big.Int).Mod(new(big.Int).Mul(vPow, v), bn256.Order)
		}
	}

	klog.V(2).Infof("y_XR %s\n", y_XR.String())
	klog.V(2).Infof("vPow %s\n", vPow.Text(16))
	klog.V(2).Infof("v %s\n", v.Text(16))

	k_sk := RandomScalarFixed()
	k_r := RandomScalarFixed()
	k_b := RandomScalarFixed()
	k_tau := RandomScalarFixed()

	A_y := new(bn256.G1).ScalarMult(&gR, k_sk)
	A_D := new(bn256.G1).ScalarMult(params.G, k_r)
	A_b := new(bn256.G1).ScalarMult(params.G, k_b)
	t1 := new(bn256.G1).ScalarMult(&CrnR, zs[1])
	d1 := new(bn256.G1).ScalarMult(&DR, new(big.Int).Mod(new(big.Int).Neg(zs[0]), bn256.Order))
	d1 = new(bn256.G1).Add(d1, t1)
	d1 = new(bn256.G1).ScalarMult(d1, k_sk)
	A_b = new(bn256.G1).Add(A_b, d1)

	A_X := new(bn256.G1).ScalarMult(&y_XR, k_r)

	A_t := new(bn256.G1).ScalarMult(params.G, new(big.Int).Mod(new(big.Int).Neg(k_b), bn256.Order))
	A_t = new(bn256.G1).Add(A_t, new(bn256.G1).ScalarMult(params.H, k_tau))

	A_u := new(bn256.G1)

	{
		var input []byte
		input = append(input, []byte(PROTOCOL_CONSTANT)...)
		input = append(input, convertbiginttobyte(s.roothash)...)

		point := HashToPoint(HashtoNumber(input))

		A_u = new(bn256.G1).ScalarMult(point, k_sk)
	}

	klog.V(2).Infof("A_y %s\n", A_y.String())
	klog.V(2).Infof("A_D %s\n", A_D.String())
	klog.V(2).Infof("A_b %s\n", A_b.String())
	klog.V(2).Infof("A_X %s\n", A_X.String())
	klog.V(2).Infof("A_t %s\n", A_t.String())
	klog.V(2).Infof("A_u %s\n", A_u.String())

	{
		var input []byte
		input = append(input, convertbiginttobyte(x)...)
		input = append(input, A_y.Marshal()...)
		input = append(input, A_D.Marshal()...)
		input = append(input, A_b.Marshal()...)
		input = append(input, A_X.Marshal()...)
		input = append(input, A_t.Marshal()...)
		input = append(input, A_u.Marshal()...)
		proof.c = reducedhash(input)
	}

	proof.s_sk = new(big.Int).Mod(new(big.Int).Mul(proof.c, witness.SecretKey), bn256.Order)
	proof.s_sk = new(big.Int).Mod(new(big.Int).Add(proof.s_sk, k_sk), bn256.Order)

	proof.s_r = new(big.Int).Mod(new(big.Int).Mul(proof.c, witness.R), bn256.Order)
	proof.s_r = new(big.Int).Mod(new(big.Int).Add(proof.s_r, k_r), bn256.Order)

	proof_c_neg := new(big.Int).Mod(new(big.Int).Neg(proof.c), bn256.Order)
	dummyA_X := new(bn256.G1).ScalarMult(&y_XR, proof.s_r) //, new(bn256.G1).ScalarMult(anonsupport.C_XR, proof_c_neg) )

	klog.V(2).Infof("dummyA_X %s\n", dummyA_X.String())
	klog.V(2).Infof("s_r %s\n", proof.s_r.Text(16))
	// klog.V(2).Infof("C_XR %s\n", anonsupport.C_XR.String())
	klog.V(2).Infof("C %s\n", proof.c.Text(16))
	klog.V(2).Infof("C_neg %s\n", proof_c_neg.Text(16))
	//  klog.V(2).Infof("A_X %s\n", sigmasupport.A_X.String())
	w_transfer := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).SetUint64(uint64(witness.TransferAmount)), zs[0]), bn256.Order)
	w_balance := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).SetUint64(uint64(witness.Balance)), zs[1]), bn256.Order)
	w_tmp := new(big.Int).Mod(new(big.Int).Add(w_transfer, w_balance), bn256.Order)
	w_tmp = new(big.Int).Mod(new(big.Int).Mul(w_tmp, wPow), bn256.Order)
	w_tmp = new(big.Int).Mod(new(big.Int).Mul(w_tmp, proof.c), bn256.Order)
	proof.s_b = new(big.Int).Mod(new(big.Int).Add(w_tmp, k_b), bn256.Order)

	proof.s_tau = new(big.Int).Mod(new(big.Int).Mul(tauX, wPow), bn256.Order)
	proof.s_tau = new(big.Int).Mod(new(big.Int).Mul(proof.s_tau, proof.c), bn256.Order)
	proof.s_tau = new(big.Int).Mod(new(big.Int).Add(proof.s_tau, k_tau), bn256.Order)

	klog.V(2).Infof("proof.c %s\n", proof.c.Text(16))
	klog.V(2).Infof("proof.s_sk %s\n", proof.s_sk.Text(16))
	klog.V(2).Infof("proof.s_r %s\n", proof.s_r.Text(16))
	klog.V(2).Infof("proof.s_b %s\n", proof.s_b.Text(16))
	klog.V(2).Infof("proof.s_tau %s\n", proof.s_tau.Text(16))

	hPrimes := params.Hs.Hadamard(ys.Invert().vector)
	hExp := ys.Times(z).Add(NewFieldVector(twoTimesZs))

	P1 := new(bn256.G1).Add(proof.BA, new(bn256.G1).ScalarMult(proof.BS, x))
	z_neg := new(big.Int).Mod(new(big.Int).Neg(z), bn256.Order)

	P1 = new(bn256.G1).Add(P1, new(bn256.G1).ScalarMult(params.Gs.Sum(), z_neg))
	P1 = new(bn256.G1).Add(P1, hPrimes.Commit(hExp.vector))

	P1 = new(bn256.G1).Add(P1, new(bn256.G1).ScalarMult(params.H, new(big.Int).Mod(new(big.Int).Neg(proof.mu), bn256.Order)))

	o := reducedhash(convertbiginttobyte(proof.c))

	u_x := new(bn256.G1).ScalarMult(params.G, o)
	P1 = new(bn256.G1).Add(P1, new(bn256.G1).ScalarMult(u_x, proof.that))
	klog.V(2).Infof("o %s\n", o.Text(16))
	klog.V(2).Infof("x %s\n", x.Text(16))
	klog.V(2).Infof("u_x %s\n", u_x.String())
	klog.V(2).Infof("p %s\n", P1.String())
	klog.V(2).Infof("hPrimes length %d\n", len(hPrimes.vector))

	primebase := NewGeneratorParams3(u_x, params.Gs, hPrimes) // trigger sigma protocol
	ipstatement := &IPStatement{PrimeBase: primebase, P: P1}
	ipwitness := &IPWitness{L: lPoly.Evaluate(x), R: rPoly.Evaluate(x)}

	for i := range ipwitness.L.vector {
		klog.V(2).Infof("L %d %s \n", i, ipwitness.L.vector[i].Text(16))
	}

	for i := range ipwitness.R.vector {
		klog.V(2).Infof("R %d %s \n", i, ipwitness.R.vector[i].Text(16))
	}

	proof.ip = NewInnerProductProof(ipstatement, ipwitness, o)

	return &proof

}
