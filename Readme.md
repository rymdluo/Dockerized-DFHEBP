# Dockerized version of DHEBP

`captain-definition` file is included for [CapRover](https://github.com/caprover/caprover) support.

Changed the 2 sample transaction amounts and ring sizes from main.go to generate alternative results from the original:
- 32 DERO and 32 ring size
- 64 DERO and 64 ring size

Output:
```
2020-08-15T18:57:31.258278356Z DERO HOMOMORPHIC PROTOCOL ( pre-alpha version )
2020-08-15T18:57:31.258282077Z 
2020-08-15T18:57:31.259378694Z I0815 18:57:31.258913 189 main.go:54] sender 
2020-08-15T18:57:31.259401985Z x (secretkey): 1aef7b4406847033ae900847419a76f32a57b123fd4f2e188046c4ec25a3c0bb
2020-08-15T18:57:31.259406041Z y: bn256.G1(15469aaa68867584a1248c1e177109371d6162b309fd7ebea20430bf06f4a57e, 0719ba6175e4f4effd5be4ddafa5625e5fcce20c5cfde14580eda4cbf0220b1b)
2020-08-15T18:57:31.259412462Z I0815 18:57:31.259204 189 main.go:55] receiver 
2020-08-15T18:57:31.259415375Z x (secretkey): 1f3514f58514e989b690dd738dc56aa8c87574e60088a3b74398d587f804a79e
2020-08-15T18:57:31.259418616Z y: bn256.G1(1b510933ecc6b4327ecd56309983bf819f6bdf65d34af685bc9c88a8c62b3bbb, 1af5e3a37bd682a19321c7db6bb2d99a37397e5940eabe1ada24b7920ef6874f)
2020-08-15T18:57:32.777374937Z I0815 18:57:32.777106 189 blockchain.go:141] User bn256.G1(15469aaa68867584a1248c1e177109371d6162b309fd7ebea20430bf06f4a57e, 0719ba6175e4f4effd5be4ddafa5625e5fcce20c5cfde14580eda4cbf0220b1b) funded 150
2020-08-15T18:57:32.780991369Z I0815 18:57:32.780732 189 main.go:98] 
2020-08-15T18:57:32.781062970Z 
2020-08-15T18:57:32.781068779Z Creating Transaction
2020-08-15T18:57:33.357848592Z I0815 18:57:33.357663 189 main.go:101] Transferring 32 from sender to receiver (ring size 32) tx size 6941 bytes 
2020-08-15T18:57:33.357887447Z I0815 18:57:33.357706 189 main.go:102] Total tx size 6941 bytes ( 4288 byte statement, 2653 bytes proof ) 
2020-08-15T18:57:33.727885836Z I0815 18:57:33.727558 189 main.go:107] Transfer successful
2020-08-15T18:57:33.731495151Z I0815 18:57:33.731141 189 main.go:116] Sender Balance 150 - 32 = 118
2020-08-15T18:57:33.731567935Z I0815 18:57:33.731214 189 main.go:117] Receiver Balance 0 + 32 = 32
2020-08-15T18:57:33.738681754Z I0815 18:57:33.738502 189 main.go:98] 
2020-08-15T18:57:33.738725431Z 
2020-08-15T18:57:33.738729182Z Creating Transaction
2020-08-15T18:57:34.620272496Z I0815 18:57:34.619918 189 main.go:101] Transferring 64 from sender to receiver (ring size 64) tx size 11493 bytes 
2020-08-15T18:57:34.620338033Z I0815 18:57:34.620149 189 main.go:102] Total tx size 11493 bytes ( 8512 byte statement, 2981 bytes proof ) 
2020-08-15T18:57:35.271463041Z I0815 18:57:35.271171 189 main.go:107] Transfer successful
2020-08-15T18:57:35.275132185Z I0815 18:57:35.274834 189 main.go:116] Sender Balance 118 - 64 = 54
2020-08-15T18:57:35.275207877Z I0815 18:57:35.274891 189 main.go:117] Receiver Balance 32 + 64 = 96
2020-08-15T18:57:35.275213609Z I0815 18:57:35.274901 189 main.go:74] 
2020-08-15T18:57:35.275216816Z Successful
```

# Original Readme.md from [source](https://git.dero.io/Captain/DHEBP):

# DHEBP (DERO Homomorphic Encryption Blockchain Protocol)
## DHEBP alpha code to demonstrate FHE blockchain transactions.

### Transaction Details:  

Each transaction consists of 2 parts:
1. Statement which contains ring members keys, commitments, encrypted balances ( this grows linear )  basicaly 4 curve points per ring member.
1. Proof which grows log  in ring members for Eg :  
8 ring size proof is only 1997 bytes  
512 ring size proof is only 3965 bytes
  
#### Ring Size, Tx Size data  
```
Ring size, tx size (fixed) in bytes irrespective of balance
2      1669 bytes   (    328 byte statement, 1341 bytes proof )  
4      2261 bytes   (    592 byte statement, 1669 bytes proof )  
8      3117 bytes   (   1120 byte statement, 1997 bytes proof )  
16     4501 bytes   (   2176 byte statement, 2325 bytes proof )  
32     6941 bytes   (   4288 byte statement, 2653 bytes proof )  
64    11493 bytes   (   8512 byte statement, 2981 bytes proof )  
128   20269 bytes   (  16960 byte statement, 3309 bytes proof ) 
256   37493 bytes   (  33856 byte statement, 3637 bytes proof )  
512   71613 bytes   (  67648 byte statement, 3965 bytes proof )
```


 

### Build  
1. Switch to directory containing this Readme.md file
1. export GOPATH=`pwd`
1. go run *.go  

##### Note: Developed and tested on linux go version 1.12.7    

### Output Sample  
```
Creating Transaction
I0706 16:05:28.258801   93136 main.go:101] Transferring 10 from sender to receiver (ring size 8) tx size 3117 bytes 
I0706 16:05:28.258810   93136 main.go:102] Total tx size 3117 bytes   (  1120 byte statement, 1997 bytes proof )  
I0706 16:05:28.341387   93136 main.go:107] Transfer successful
I0706 16:05:28.343528   93136 main.go:116]       Sender Balance        150 -        10 =       140
I0706 16:05:28.343533   93136 main.go:117]     Receiver Balance          0 +        10 =        10
I0706 16:05:28.345662   93136 main.go:98] 

Creating Transaction
I0706 16:05:28.568605   93136 main.go:101] Transferring 90 from sender to receiver (ring size 16) tx size 4501 bytes 
I0706 16:05:28.568614   93136 main.go:102] Total tx size 4501 bytes   (  2176 byte statement, 2325 bytes proof )  
I0706 16:05:28.680647   93136 main.go:107] Transfer successful
I0706 16:05:28.682788   93136 main.go:116]       Sender Balance        140 -        90 =        50
I0706 16:05:28.682792   93136 main.go:117]     Receiver Balance         10 +        90 =       100
I0706 16:05:28.682796   93136 main.go:74] 
                        Successful
```





