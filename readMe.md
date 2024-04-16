# Algorithm

p: prime order
n: group order
prk: privateKey
pbk = curve.g.multiply(privateKey) // calculate publicKey from privateLey
M: message
k: random number
r = curve.g.multiply(k) // like calculate publicKey from privateLey
e = H(M)
s = (k + privateKey\*e) mod curve.n
Return (e, s)

# In Card

1. Generate keyPair scep256k1
2. Generate random number
3. Get msgHash from App
4. Perform signature algorithm and return (e, s)

# In App

1. Generate msg and msgHash
2. Push msgHash to App
3. Get (e, s) and start verifying

4. # File
1. Signature_Single.js: only need to test this file. If it is ok, then Signature_Multiple.js will be executed the same
