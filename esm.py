import numpy as np
from Pyfhel import Pyfhel

# utilities to generate context parameters
bitsize = lambda x: np.ceil(np.log2(x))
get_closest_power_of_two = lambda x: int(2 ** (bitsize(x)))


class EncryptedStringMatcher:
    """
    A class that provides functionality for matching encrypted strings
    without revealing their plaintext content.
    """

    def __init__(self, l=256, sec=128, use_n_min=True):
        """
        Initializes the homomorphic encryption context.

        Parameters:
        - l (int): Expected maximum size of strings to be encrypted.
        - sec (int): Security level for the encryption (128, 192, or 256).
        - use_n_min (bool): Whether to use the minimum n for the encryption context.
        """
        self.HE = self._get_BFV_context_hammingDist(l, sec, use_n_min)
        self.HE.keyGen()
        self.HE.relinKeyGen()
        self.HE.rotateKeyGen()

    def _get_BFV_context_hammingDist(self, l, sec, use_n_min):
        """
        Determines and returns the optimal parameters for the BFV encryption scheme
        to compute the Hamming distance.

        Parameters:
        - l (int): Vector length, roughly correlating to the string length.
        - sec (int): Security level.
        - use_n_min (bool): Whether to use the minimum n for the encryption context.

        Returns:
        - Pyfhel object: Context to perform homomorphic encryption.
        """
        # > OPTIMAL t --> minimum for chosen `n`, or big enough to hold v1@v2
        t_bits_min = 17
        t_bits = max(t_bits_min, 2 * bitsize(l))
        if t_bits > 60:
            raise ValueError(f"t_bits = {t_bits} > 60.")

        # > OPTIMAL n
        n_min = 2**12 if sec in [128, 192] else 2**13
        if use_n_min:
            n = n_min  # use n_min regardless of l
        elif 2 * l < n_min:
            n = n_min  # Smallest
        elif 2 * l > 2**15:
            n = 2**15  # Largest
        else:
            n = get_closest_power_of_two(2 * l)

        context_params = {
            "scheme": "BFV",
            "n": n,  # Poly modulus degree. BFV ptxt is a n//2 by 2 matrix.
            "t_bits": t_bits,  # Plaintext modulus.
            "sec": sec,  # Security level.
        }

        # Increasing `n` to get enough noise budget for the c1*c2 multiplication.
        #  Since the noise budget in a multiplication consumes t_bits (+...) noise
        #  budget and we start with `total_coeff_modulus_bit_count-t_bits` budget, #  we check if this is high enough to decrypt correctly.
        HE = Pyfhel()
        total_coeff_modulus_bit_count = 0
        while total_coeff_modulus_bit_count - 2 * t_bits <= 0:
            context_status = HE.contextGen(**context_params)
            total_coeff_modulus_bit_count = HE.total_coeff_modulus_bit_count
            # if (context_status != "success"):
            #     warnings.warn(f"  n={context_params['n']} Doesn't produce valid parameters. Trying 2*n")
            context_params["n"] *= 2
            if context_params["n"] > 2**15:
                raise ValueError(
                    f"n = {context_params['n']} > 2**15. Parameters are not valid."
                )
        return HE

    def string_to_binary_vector(self, text: str, char_length=16):
        """
        Converts a string to its binary representation.

        Parameters:
        - text (str): The input string to convert.
        - char_length (int): The bit-length for each character encoding.

        Returns:
        - np.array: The binary representation of the string.
        """
        return np.array(
            [int(bit) for char in text for bit in format(ord(char), f"0{char_length}b")]
        )

    def binary_vector_to_string(self, vec, char_length=16) -> str:
        """
        Converts a binary vector back to its string representation.

        Parameters:
        - vec: The binary representation of a string.
        - char_length (int): The bit-length for each character encoding.

        Returns:
        - str: The decoded string.
        """
        return "".join(
            chr(int("".join(map(str, vec[i : i + char_length])), 2))
            for i in range(0, len(vec), char_length)
        )

    def encrypt_string(self, text):
        """
        Encrypts a given string.

        Parameters:
        - text (str): The input string to encrypt.

        Returns:
        - list: A list of encrypted chunks representing the string.
        """
        vec = self.string_to_binary_vector(text)
        return [
            self.HE.encrypt(vec[j : j + self.HE.get_nSlots()])
            for j in range(0, len(vec), self.HE.get_nSlots())
        ]

    def decrypt_string(self, encrypted_vec):
        """
        Decrypts an encrypted string vector back to plaintext.

        Parameters:
        - encrypted_vec (list): List of encrypted chunks.

        Returns:
        - str: The decrypted string.
        """
        decrypted_vec = []
        for ct in encrypted_vec:
            decrypted_vec.extend(self.HE.decrypt(ct))
        return self.binary_vector_to_string(np.array(decrypted_vec))

    def are_strings_equal(self, enc_str1, enc_str2):
        """
        Determines if two encrypted strings are exactly the same using the Hamming distance.

        Parameters:
        - enc_str1 (list): First encrypted string.
        - enc_str2 (list): Second encrypted string.

        Returns:
        - bool: True if strings are equal, False otherwise.
        """
        # This is the easy and boring way to do it
        # if len(enc_str1) != len(enc_str2):
        #     return False
        hamming_distance = self._compute_hamming_distance(enc_str1, enc_str2)
        return hamming_distance == 0

    def _compute_hamming_distance(self, enc_vec1, enc_vec2):
        """
        Computes the Hamming distance between two encrypted vectors.

        Parameters:
        - enc_vec1 (list): First encrypted vector.
        - enc_vec2 (list): Second encrypted vector.

        Returns:
        - int: The computed Hamming distance.
        """
        c_sp = self.HE.cumul_add(
            sum([~(enc_vec1[i] * enc_vec2[i]) for i in range(len(enc_vec1))])
        )
        # TODO: It should be possible to do this without decrypting by using homomorphic operations
        sumx = np.expand_dims(np.sum([self.HE.decrypt(c) for c in enc_vec1]), 0)
        sumy = np.expand_dims(np.sum([self.HE.decrypt(c) for c in enc_vec2]), 0)
        c1_sumx = self.HE.encrypt(sumx)
        c2_sumy = self.HE.encrypt(sumy)
        c_hd = c1_sumx + c2_sumy - (c_sp * 2)
        hamming_distance = self.HE.decrypt(c_hd)[0]
        # Print out some debugging information
        print("vec1 length:", len(enc_vec1))
        print("vec2 length:", len(enc_vec2))
        print("c1_sumx:", self.HE.decrypt(c1_sumx))
        print("c2_sumy:", self.HE.decrypt(c2_sumy))
        print("c_sp:", self.HE.decrypt(c_sp))
        print("hamming_distance:", hamming_distance)
        return hamming_distance
