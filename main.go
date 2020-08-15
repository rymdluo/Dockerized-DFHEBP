package main

import "fmt"
import "flag"

import "github.com/kubernetes/klog"
import "github.com/clearmatics/bn256"

const POINT_SIZE = 33        // this can be optimized to 33 bytes
const FIELDELEMENT_SIZE = 32 // why not have bigger curves

const RING_SIZE = 8 // use powers of 2, note this is not currently sanity checked

// protocol supports amounts upto this, however this pre=alpha wallet supports only 65535 as we use bruteforce to decode balance
const MAX_AMOUNT = 18446744073709551616 // 2^64 - 1,, current  wallet supports amounts of only 65535 are supported

const PROTOCOL_CONSTANT = "DERO"

// as you can see overhead per account is 3 curve points, , user public key, 2 points for encrypted balances
type Blockchain struct {
	registeredusers map[string]*bn256.G1 // registered users,, public key  of user
	balances        map[string]*Balance  // encrypted balances of registered users
}

type Balance struct { // all balances are kept here and overhead of per account in blockchain is 66 bytes
	C [2]bn256.G1
}

func init() {
	klog.InitFlags(nil) // setup logging
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "WARNING")
	flag.Set("v", "0") // set this to 1 or 2 to enable verbose logging
	flag.Parse()

}

func main() {

	fmt.Printf("\n\n				DERO HOMOMORPHIC PROTOCOL  ( pre-alpha version )\n\n")

	blockchain := init_blockchain() // init memory map based chain to validate concept
	sender := GenerateKeyPair()
	receiver := GenerateKeyPair()

	if err := blockchain.registerUser(sender); err != nil { // register sender
		panic(err)
	}

	if err := blockchain.registerUser(receiver); err != nil { // register receiver
		panic(err)
	}

	klog.V(0).Infof("sender \n%s\n", *sender)
	klog.V(0).Infof("receiver \n%s\n", *receiver)

	var dummies []*KeyPair // generate dummies to be used as anonymous groups
	for i := 0; i < 2100; i++ {
		dummies = append(dummies, GenerateKeyPair())                // generate a random user
		if err := blockchain.registerUser(dummies[i]); err != nil { // register a user
			panic(err)
		}
	}

	// this basicaly is a mining transaction, in this poc  you can give any one any balance
	if err := blockchain.FundUser(sender.y, 150); err != nil { // sender now has balance 150
		panic(err)
	}

	// do 2 transfers, one of 32, other 64 with ring size 32 and 64 respectively
	blockchain.transfer(sender, receiver, 32, dummies, 32)  // transfer 32 from sender to receiver ring size 32
	blockchain.transfer(sender, receiver, 64, dummies, 64) // transfer 64 from sender to receiver, ring size 64

	klog.V(0).Infof("\n\t\t\tSuccessful\n")
}



// wrap transfer in a function for better understanding of users
func (blockchain *Blockchain) transfer(sender, receiver *KeyPair, amount uint32, dummies []*KeyPair, ring_size int) {

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Transfer failed ", r)
		}
	}()

	sender_balance_before_transfer, _ := blockchain.ReadBalance(sender.y, sender.x)       // find balance via bruteforce
	receiver_balance_before_transfer, _ := blockchain.ReadBalance(receiver.y, receiver.x) // find balance via bruteforce

	var anonlist []*bn256.G1           // choose anonymous peers, this should be done carefully
	for i := 0; i < ring_size-2; i++ { // it must (2^n) -2 ,  example 2,6,14,30,62, 126,254,510,1022,2046 etc
		anonlist = append(anonlist, dummies[i].y)
	}

	transfer_amount := amount // total value to transfer

	klog.V(0).Infof("\n\nCreating Transaction")
	tx := blockchain.BuildTransaction(sender, receiver.y, transfer_amount, anonlist) // generate proof for sending value 10

	klog.V(0).Infof("Transferring %d from sender to receiver (ring size %d) tx size %d bytes ", transfer_amount, len(anonlist)+2, tx.Size())
	klog.V(0).Infof("Total tx size %d bytes   (  %d byte statement, %d bytes proof )  ", tx.Size(), tx.statement.Size(), tx.proof.Size())

	// at this point tx has strong anonymity and deniablity and leak proof, you are welcome to analyse it for any leakages

	if blockchain.ExecuteTransaction(tx) {
		klog.V(0).Infof("Transfer successful")
	} else {
		klog.Fatalf("Transfer failed. please enable logs")
		return
	}

	sender_balance_after_transfer, _ := blockchain.ReadBalance(sender.y, sender.x)       // find balance via bruteforce
	receiver_balance_after_transfer, _ := blockchain.ReadBalance(receiver.y, receiver.x) // find balance via bruteforce

	klog.V(0).Infof("%20s  %9d - %9d = %9d\n", "Sender Balance", sender_balance_before_transfer, transfer_amount, sender_balance_after_transfer)
	klog.V(0).Infof("%20s  %9d + %9d = %9d\n", "Receiver Balance", receiver_balance_before_transfer, transfer_amount, receiver_balance_after_transfer)

	if (sender_balance_before_transfer-transfer_amount) != sender_balance_after_transfer ||
		(receiver_balance_before_transfer+transfer_amount) != receiver_balance_after_transfer {
		panic("something failed.. jump in")
	}
}
