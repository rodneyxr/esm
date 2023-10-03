# Encrypted String Matcher (ESM) Library
The `EncryptedStringMatcher` class provides encrypted string matching functionality, allowing for the comparison of encrypted strings without exposing their plaintext content. It uses homomorphic encryption, specifically the BFV scheme, to allow for string operations in the encrypted domain.

## Prerequisites

`esm` requires the following packages to be installed:

```shell
pip install Pyfhel
```

Refer to the [Pyfhel](https://pyfhel.readthedocs.io/en/latest/source/getting_started/1_installation.html) documentation for more information on how to install the Pyfhel library.

## Usage Scenario

This library is particularly useful in situations where data privacy or security is paramount. For instance, it can be used to compare strings stored in encrypted databases without revealing their actual content.

```python
from esm import EncryptedStringMatcher

matcher = EncryptedStringMatcher()

s1 = matcher.encrypt_string("hello world")
s2 = matcher.encrypt_string("hello world")
assert matcher.are_strings_equal(s1, s2) == True

s1 = matcher.encrypt_string("hello world")
s2 = matcher.encrypt_string("bye world")
assert matcher.are_strings_equal(s1, s2) == False
```

## Main Features

1. **Encrypt and Decrypt Strings:** Convert plaintext strings into encrypted vectors and vice versa.
2. **Exact String Matching:** Compare two encrypted strings to determine if they are exactly the same.

## Future Features
1. **Substring Matching:** Check if an encrypted string contains a given encrypted substring.

## Key Methods and Their Descriptions

- `__init__(self, l=256, sec=128, use_n_min=True)`: Initializes the homomorphic encryption context.

- `encrypt_string(self, text)`: Converts a plaintext string into a binary vector, then encrypts and returns it.

- `decrypt_string(self, encrypted_vec)`: Decrypts an encrypted vector and converts it back to a plaintext string.

- `are_strings_equal(self, enc_str1, enc_str2)`: Determines if two encrypted strings are exactly the same using the Hamming distance. A Hamming distance of zero indicates that the strings are identical.

## Internal Utilities

- `string_to_binary_vector(self, text, char_length=16)`: Converts a plaintext string to a binary vector based on Unicode character values.

- `binary_vector_to_string(self, vec, char_length=16)`: Converts a binary vector back to a plaintext string.

- `_compute_hamming_distance(self, enc_vec1, enc_vec2)`: Computes the Hamming distance between two encrypted vectors. This method is used to determine the similarity between two encrypted strings.

## TODO

- `is_substring_present(self, encrypted_text, encrypted_substring)`: Checks if an encrypted string contains a given encrypted substring.