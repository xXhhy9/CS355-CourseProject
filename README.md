# CS355-CourseProject (Alice and Bob)

# Code Segment Generation
```
dd if=/dev/urandom of=segment.bin bs=1M count=500
```

# Library
```
pip install cryptography
```

# Problem:
    The setting of this project is that Alice and Bob each have 5 files of ~500MB each. The goal is for Alice and Bob to confirm whether or not they have the same files without physically transferring the files to each other to check.

# Security goals:
    After careful consideration of the parameters of the project, we identified that to solve Alice and Bob's problem we would need a communication system that upheld authenticity, integrity, and confidentiality.

# How the security goals are met:
    Starting with a simple TCP connection we have identified that it is an unauthenticated channel that upholds none of the security goals. To start, we hash and mac our messages using SHA-256 and MACs before sending them through the channel. As a result, the unauthenticated channel is converted into an authenticated channel which upholds the security goals of integrity, from the hashing, and authenticity, from the MACs. Finally, to meet the last security goal we would need to convert the authenticated channel into a secure channel. This could be done through the use of an encryption process, in our case we decided on the advanced encryption standard (AES).

    As a side note, all key security standards are guaranteed through the use of elliptic curve cryptography key exchange (ECC key exchange) which is based on DLOG being hard.
    
    In conclusion, given an unauthenticated channel, we used HMACs to convert it into an authenticated channel and AES encryption to convert it into a secure channel. By doing so, we have guaranteed authenticity, integrity, and confidentiality between Alice and Bob.
