"""
Module for handling constants declarations.
"""


class ConstantsNamespace:
    """Class that works as a namespace for constants."""
    @property
    def BASE16(self):
        """Base 16"""
        return 16

    @property
    def BASE32(self):
        """Base 32"""
        return 32

    @property
    def BYTE_LENGTH(self):
        """Length of the time-based counter in bytes"""
        return 8

    @property
    def CHARACTER_SET(self):
        """Symbol alphabet for Base32"""
        return list("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    @property
    def NUM_CHARS_IN_GROUPS(self):
        """Number of hex chars in each of the groups that form the hash"""
        return 2

    @property
    def SECRET_LENGTH(self):
        """Length of the secret, for hash generation"""
        return 32

    @property
    def TIME_STEP_IN_SECONDS(self):
        """Timestep, to establish our "moving factor" (RFC 6238)"""
        return 30

    @property
    def TRUNCATED_HASH_LENGTH(self):
        """Hex digits for the final truncated hash, a 4-byte hash string"""
        return 8

    @property
    def XOR_MASK(self):
        """Mask to apply an XOR to a truncated hash, ensuring that the 32-bit value won't be signed
        (RFC 6238 recommendation)"""
        return 0x7FFFFFFF


class TestConstantsNamespace:
    """Namespace for constants used in testing"""
    @property
    def TEST_NUM_DIGITS(self):
        """Hex digits for the truncated hash string"""
        return 8

    @property
    def TEST_SECRET(self):
        """Secret for hmac generation"""
        return "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
