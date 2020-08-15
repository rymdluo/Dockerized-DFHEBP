package main

import "fmt"
import "math/big"
import "crypto/rand"

import mrand "math/rand"
import "encoding/binary"

//import "encoding/hex"

import "github.com/kubernetes/klog"
import "github.com/clearmatics/bn256"

type KeyPair struct {
	x *big.Int
	y *bn256.G1
}

func (k KeyPair) String() string {
	x := fmt.Sprintf("x (secretkey): %x\n", k.x)
	x += fmt.Sprintf("y: %s", k.y)
	return x
}

var G *bn256.G1 = NewGeneratorParams(1).G // global generator point

// ToDo encode the balance so only the receiver can decode  transferred amount easily
type Statement struct {
	CLn           []*bn256.G1
	CRn           []*bn256.G1
	Publickeylist []*bn256.G1 // Todo these can be skipped and collected back later on from the chain, this will save ringsize * POINTSIZE bytes
	C             []*bn256.G1 // commitments
	D             *bn256.G1

	roothash *big.Int // note roothash contains the merkle root hash of chain, when it was build

}

type Witness struct {
	SecretKey      *big.Int
	R              *big.Int
	TransferAmount uint32 // total value being transferred
	Balance        uint32 // whatever is the the amount left after transfer
	index          []int  // index of sender in the public key list

}

type Transaction struct {
	statement *Statement
	proof     *Proof
}

func RandomScalar() *big.Int {
	a, _ := rand.Int(rand.Reader, bn256.Order)
	return a
}

// this will return fixed random scalar
func RandomScalarFixed() *big.Int {
	return RandomScalar()
}

func GenerateKeyPair() *KeyPair {
	var k KeyPair
	var y bn256.G1
	k.x = RandomScalar()
	k.y = &y
	y.ScalarMult(G, k.x)

	return &k
}

// this basically does a  Schnorr ignature
func sign(address *big.Int, k *KeyPair) (c, s *big.Int) {
	var tmppoint bn256.G1
	tmpsecret := RandomScalar()
	tmppoint.ScalarMult(G, tmpsecret)

	serialize := []byte(fmt.Sprintf("%s%s", k.y.String(), tmppoint.String()))

	c = reducedhash(serialize)
	s = new(big.Int).Mul(c, k.x) // basicaly scalar mul add
	s = s.Mod(s, bn256.Order)
	s = s.Add(s, tmpsecret)
	s = s.Mod(s, bn256.Order)

	return
}

func init_blockchain() *Blockchain {
	return &Blockchain{registeredusers: map[string]*bn256.G1{}, balances: map[string]*Balance{}}
}

func (b *Blockchain) registerUser(u *KeyPair) error {
	c, s := sign(new(big.Int).SetUint64(0), u)
	return b.RegisterUser(u.y, c, s)

}

// register a user to blockchain
// this must be done via a empty transaction
// however, such transactions must themselves have some proof of work (independent from mining PoW) so as
// to avoid creation of billions of dummy accounts
// also, note we should have some sort of account destruction mechanism if someone wishes to do so,
// the leftover balance (if not empty can be donated and so on)
// will allow user u
func (b *Blockchain) RegisterUser(u *bn256.G1, c, s *big.Int) error {

	tmppoint := new(bn256.G1).Add(new(bn256.G1).ScalarMult(G, s), new(bn256.G1).ScalarMult(u, new(big.Int).Neg(c)))

	serialize := []byte(fmt.Sprintf("%s%s", u.String(), tmppoint.String()))

	c_calculated := reducedhash(serialize)

	if c.String() != c_calculated.String() {
		return fmt.Errorf("Registration signature is invalid")
	}

	if _, ok := b.registeredusers[u.String()]; ok {
		return fmt.Errorf("Already Registered ")
	} else {
		b.registeredusers[u.String()] = u
		var balance Balance
		balance.C[0].Set(u)
		balance.C[1].Set(G)
		b.balances[u.String()] = &balance
	}

	return nil
}

// fund a a user any arbitrary amount
func (b *Blockchain) FundUser(u *bn256.G1, amount uint32) error {

	if _, ok := b.registeredusers[u.String()]; !ok {
		return fmt.Errorf("user not Registered ")
	} else {
		balance := b.balances[u.String()]
		balance.C[0].Add(&balance.C[0], new(bn256.G1).ScalarMult(G, new(big.Int).SetUint64(uint64(amount))))
		klog.Infof("User %s  funded %d", u.String(), amount)
		return nil
	}

}

// fund a a user any arbitrary amount
// this is a pure bruteforce, but can be optimized to instantly report under most of the conditions
func (b *Blockchain) ReadBalance(u *bn256.G1, secretkey *big.Int) (uint32, error) {

	if _, ok := b.registeredusers[u.String()]; !ok {
		return 0, fmt.Errorf("user not Registered ")
	}
	balance := b.balances[u.String()]

	var CL, CR, gb bn256.G1
	CL.Set(&balance.C[0])
	CR.Set(&balance.C[1])

	gb.Add(&CL, new(bn256.G1).Neg(new(bn256.G1).ScalarMult(&CR, secretkey)))

	var acc bn256.G1
	acc.ScalarMult(G, new(big.Int).SetUint64(0))

	var tmp bn256.G1 // avoid allocation every loop
	for i := 0; i <= 65536; i++ {
		if acc.String() == gb.String() {
			return uint32(i), nil
		}
		tmp.Set(&acc)
		acc.Add(&tmp, G)
	}

	klog.Fatalf("balance not found or > 65535\n")
	return 0, nil
}

// this currently does not do semantic checks
func (b *Blockchain) ExecuteTransaction(tx *Transaction) bool {

	// Todo check whether all the  public keys exist in the chain or not
	for i := range tx.statement.Publickeylist {
		if _, ok := b.balances[tx.statement.Publickeylist[i].String()]; !ok { // note these are pointer and updated real time
			return false
		}
	}

	if tx.proof.Verify(tx.statement) {
		// this should be atomic, either all should be done or none at all
		for i := range tx.statement.Publickeylist {
			ebalance := b.balances[tx.statement.Publickeylist[i].String()] // note these are pointer and updated real time

			ebalance.C[0].Add(new(bn256.G1).Set(&ebalance.C[0]), tx.statement.C[i])
			ebalance.C[1].Add(new(bn256.G1).Set(&ebalance.C[1]), tx.statement.D)
		}

		return true

	}

	return false

}

// generate proof  etc
func (b *Blockchain) BuildTransaction(sender *KeyPair, receiver_publickey *bn256.G1, value uint32, anonset_publickeys []*bn256.G1) *Transaction {

	var tx Transaction

	var publickeylist, C, CLn, CRn []*bn256.G1
	var D bn256.G1

	anonset_publickeys_copy := make([]*bn256.G1, len(anonset_publickeys))
	copy(anonset_publickeys_copy, anonset_publickeys)

	var buf [8]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic("cannot seed math/rand package with cryptographically secure random number generator")
	}
	mrand.Seed(int64(binary.LittleEndian.Uint64(buf[:]))) // mrand shuffle is backed by crypto seed

	var witness_index []int
	for i := 0; i < 2+len(anonset_publickeys); i++ { // todocheck whether this is power of 2 or not
		witness_index = append(witness_index, i)
	}

	for {
		mrand.Shuffle(len(witness_index), func(i, j int) {
			witness_index[i], witness_index[j] = witness_index[j], witness_index[i]
		})

		// make sure sender and receiver are not both odd or both even
		// sender will always be at  witness_index[0] and receiver will always be at witness_index[1]
		if witness_index[0]%2 != witness_index[1]%2 {
			break
		}
	}

	// Lots of ToDo for this, enables satisfying lots of  other things
	r := RandomScalar() // revealing this will disclose the amount and the sender and receiver and separate anonymouse rings memeber

	for i := 0; i < 2+len(anonset_publickeys); i++ {
		switch i {
		case witness_index[0]:
			publickeylist = append(publickeylist, sender.y)
		case witness_index[1]:
			publickeylist = append(publickeylist, receiver_publickey)

		default:
			publickeylist = append(publickeylist, anonset_publickeys_copy[0])
			anonset_publickeys_copy = anonset_publickeys_copy[1:]
		}

	}

	for i := range publickeylist { // setup commitments
		var x bn256.G1
		switch {
		case i == witness_index[0]:
			x.ScalarMult(G, new(big.Int).SetInt64(0-int64(value))) // decrease senders balance
		case i == witness_index[1]:
			x.ScalarMult(G, new(big.Int).SetInt64(int64(value))) // increase receiver's balance

		default:
			x.ScalarMult(G, new(big.Int).SetInt64(0))
		}

		x.Add(new(bn256.G1).Set(&x), new(bn256.G1).ScalarMult(publickeylist[i], r)) // hide all commitments behind r
		C = append(C, &x)
	}
	D.ScalarMult(G, r)

	for i := range publickeylist {
		var ll, rr bn256.G1
		ebalance := b.balances[publickeylist[i].String()] // note these are taken from the chain live

		ll.Add(&ebalance.C[0], C[i])
		CLn = append(CLn, &ll)

		rr.Add(&ebalance.C[1], &D)
		CRn = append(CRn, &rr)
	}

	// time for bullets-sigma
	statement := GenerateStatement(CLn, CRn, publickeylist, C, &D) // generate statement
	statement.roothash = new(big.Int).SetUint64(10)                // currently it is a dummy param, until blockchain hash persistance

	balance, _ := b.ReadBalance(sender.y, sender.x)
	witness := GenerateWitness(sender.x, r, value, balance-value, witness_index)

	u := new(bn256.G1).ScalarMult(HashToPoint(HashtoNumber(append([]byte(PROTOCOL_CONSTANT), convertbiginttobyte(statement.roothash)...))), sender.x) // this should be moved to generate proof
	Print(statement, witness)
	tx.statement = statement
	tx.proof = GenerateProof(statement, witness, u)

	return &tx
}

func Print(s *Statement, w *Witness) {

	for i := range s.CLn {
		klog.V(1).Infof("CLn[%d] %s\n", i, s.CLn[i].String())
	}

	for i := range s.CRn {
		klog.V(1).Infof("CRn[%d] %s\n", i, s.CRn[i].String())
	}

	for i := range s.Publickeylist {
		klog.V(1).Infof("P[%d] %s\n", i, s.Publickeylist[i].String())
	}

	for i := range s.C {
		klog.V(1).Infof("C[%d] %s\n", i, s.C[i].String())
	}

	klog.V(1).Infof("D: %s\n", s.D.String())

	klog.V(1).Infof("Merkle roothash): %s\n", s.roothash)

	klog.V(1).Infof("secretkey 0x%s\n", w.SecretKey.Text(16))
	klog.V(1).Infof("R 0x%s\n", w.R.Text(16))
	klog.V(1).Infof("Value %d\n", w.TransferAmount)
	klog.V(1).Infof("Balance %d\n", w.Balance)
	klog.V(1).Infof("index %d\n", w.index)

}

func (tx *Transaction) Size() int {
	return tx.statement.Size() + tx.proof.Size()
}
func (s *Statement) Size() int {
	return (len(s.CLn)+len(s.CRn)+len(s.Publickeylist)+len(s.C))*POINT_SIZE + 2*FIELDELEMENT_SIZE
}

// statement hash
func (s *Statement) Hash() *big.Int {
	var input []byte
	for i := range s.CLn {
		input = append(input, s.CLn[i].Marshal()...)
	}
	for i := range s.CRn {
		input = append(input, s.CRn[i].Marshal()...)
	}
	for i := range s.C {
		input = append(input, s.C[i].Marshal()...)
	}
	input = append(input, s.D.Marshal()...)
	for i := range s.Publickeylist {
		input = append(input, s.Publickeylist[i].Marshal()...)
	}
	input = append(input, convertbiginttobyte(s.roothash)...)

	return reducedhash(input)
}

// generate statement
func GenerateStatement(CLn, CRn, publickeylist, C []*bn256.G1, D *bn256.G1) *Statement {
	return &Statement{CLn: CLn, CRn: CRn, Publickeylist: publickeylist, C: C, D: D}
}

// generate witness
func GenerateWitness(secretkey, r *big.Int, TransferAmount, Balance uint32, index []int) *Witness {
	return &Witness{SecretKey: secretkey, R: r, TransferAmount: TransferAmount, Balance: Balance, index: index}
}

// converts a big int to 32 bytes, prepending zeroes
func convertbiginttobyte(x *big.Int) []byte {
	var dummy [128]byte
	joined := append(dummy[:], x.Bytes()...)
	return joined[len(joined)-32:]
}
