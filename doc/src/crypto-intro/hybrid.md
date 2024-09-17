# Hybrid encryption

Hybrid encryption attempts to balance the "weaknesses" of the individual encryption methods (symmetric and asymmetric) and benefit from both advantages.

As previously stated, there are two main advantages and disadvantages there: while symmetric encryption works faster and more efficiently, asymmetric encryption is considered more secure in certain use cases, as the key exchange between two participants of symmetric encryption can be considered problematic.

Hybrid encryption tries to benefit from the advantages of both worlds by encrypting files or secret messages symmetrically. We now encrypt the key we used to encrypt the data with the public key of the second party to whom we want to send the encrypted data. We then send both the encrypted secret message and the encrypted key to decrypt that message. Thanks to the public-key encryption, the communication partner is now able to use its private key to decrypt the symmetric key and thus efficiently decrypt the secret message. In this way, we can provide the security of asymmetric encryption and not have to worry too much about the inefficiency of the process, since no potentially large secret documents need to be encrypted, only a key of usually fixed size.
