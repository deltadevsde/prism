# Symmetric encryption

Symmetric encryption is a method of encrypting data where the same key is used for both encryption and decryption processes. This means that both the sender and the receiver need to own / know the same secret key to securely communicate with each other.

The process works as follows:

1. The sender uses the secret key to encrypt the plaintext (original message) into ciphertext (encrypted message).
2. The ciphertext is then sent to the receiver over a communication channel (eventually untrusted / public).
3. The receiver, who knows the same secret key, uses it to decrypt the ciphertext back into the plaintext.

Some popular symmetric encryption algorithms include Advanced Encryption Standard (AES) and Data Encryption Standard (DES). These algorithms are efficient and suitable for encrypting large amounts of data (which isn't the case for asymmetric encryption).

However, there are some drawbacks to symmetric encryption. The most significant challenge is securely distributing the secret key to all involved parties. If the secret key is intercepted by an unauthorized party, the security of the encrypted data is compromised. To overcome this issue, asymmetric encryption (public-key encryption) can be used in conjunction with symmetric encryption (which is called hybrid encryption and is used in some of our examples) to securely exchange secret keys.
