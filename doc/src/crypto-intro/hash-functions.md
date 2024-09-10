# Hash functions

A hash function can be conceptualized as a black box with an input and an output. This black box transforms an input, of arbitrary length, into a fixed-size string. One of the most widely recognized hash functions is the SHA256 hash function, which maps an input to a 256-bit string output. Hash functions must satisfy certain critical requirements:

- Hash functions should be **collision resistant**. That is, for each input there should be a unique output. This is theoretically impossible, as there are infinitely many potential inputs and, regardless of the number of bits used in the output, it is impossible to represent an infinite number of inputs. However, it is possible to ensure that it is computationally infeasible to create collisions in practice. For instance, if we hash the strings "Andrea" and "Andreas," the resulting outputs are as follows:
    H(Andrea) = **253387e...ba0dc32**
    H(Andreas) = **9eea624...27051c8**
    Changing even one letter in the input results in an unpredictable change in the entire hash value.
- Hash functions are **one-way functions**. That is, the calculation works in only one direction. If we want to calculate the hash of "Andrea," we can compute H(Andrea) and obtain the result 253387e...ba0dc32. However, we cannot perform the reverse calculation, so we cannot determine the input that resulted in the output value 253387e...ba0dc32. So its impossible to calculate H^-1(253387e...ba0dc32) = Andrea.
- Hash functions are **deterministic**. That is, for a given input, the same hash value is produced consistently across all calculations. Therefore, the output hash value remains constant for the same input.
