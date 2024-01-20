"""
Module for the implementation of the TOTP algorithm (RFC 6238) and helper methods.
"""
from base64 import b32decode
from hashlib import sha1
from hmac import new as new_hmac
from math import floor
from secrets import choice
from time import time
from typing import Any

from tfa import constants


def prettify_hex(hex_str: str) -> str:
    """Makes a hex number more human-readable by adding the '0x' prefix and capitalizing letters.
    For example, from 'a431e45b' to '0xA431E45B'.

    :param hex_str: truncated hexadecimal string to be formatted
    :return: a formatted hexadecimal string
    """
    return "0x" + hex_str.upper()


def secret_base32() -> str:
    """Generates a 32 character base32 secret (compatible with current OTP apps.) If we expect to
    provide client-side support with an OTP app, we need to be mindful of the app requirements. For
    example, the Google Authenticator app requires that the secret be entered in base32 encoding.

    :return: pseudo-randomly generated base32 secret
    """
    constant: Any = constants.ConstantsNamespace()
    secret = "".join(
        choice(constant.CHARACTER_SET) for _ in range(constant.SECRET_LENGTH)
    )

    return secret


def hmac_generator(secret: str, current_time: int) -> str:
    """HMAC-SHA-1 algorithm implementation (for Hash computation) to produce a message
    authentication code. It generates a 160-bit hash value (the message digest). If we could use
    SHA256 for the hash generation, it would generate a more secure (256-bit) hmac. We're using
    SHA1 to avoid future compatibility issues with current OTP apps.

    :param secret: a 32-character, base32 secret
    :param current_time: current time in seconds (unix time)
    :return: a 160-bit hash string (a message digest from the HMAC-SHA-1 algorithm)
    """
    constant: Any = constants.ConstantsNamespace()

    try:
        # time_counter will be our time-base counter -the moving factor-
        time_counter = floor(current_time / constant.TIME_STEP_IN_SECONDS)

    except ZeroDivisionError:
        time_counter = current_time

    # Convert to bytes the secret and time counter to use the new() function of the hmac module to
    #   generate the hash
    secret_in_bytes: bytes = bytes(b32decode(secret, casefold=True))
    time_counter_in_bytes: bytes = time_counter.to_bytes(constant.BYTE_LENGTH, "big")

    #  We'll combine the time counter (our "moving factor") with the secret to create a hash-based
    #    message authentication code (HMAC) object, using SHA1. That is, a SHA1 hash.
    hmac_object = new_hmac(secret_in_bytes, time_counter_in_bytes, sha1)

    # the message digest -the hash-, as a hex string
    message_digest = hmac_object.hexdigest()

    return message_digest


def truncate_hash(hash_value: str) -> str:
    """Dynamic offset truncation implementation, according to RFC 4226. This dynamic truncation
    generates a 4-byte string. The last 4 bits of the last byte of the hash_value parameter are
    used to determine the start of the offset.

    :param hash_value: a 160-bit hash string to be truncated
    :return: a 32-bit hash string, truncated from the original "hash_value" string
    """
    constant: Any = constants.ConstantsNamespace()

    truncation_offset: int = int(hash_value[-1], constant.BASE16)
    truncation_start: int = truncation_offset * constant.NUM_CHARS_IN_GROUPS
    truncation_end: int = truncation_start + constant.TRUNCATED_HASH_LENGTH

    truncated_hash = hash_value[truncation_start:truncation_end]

    return truncated_hash


def hexcode_to_otp(truncated_hash: str, num_digits: int) -> str:
    """Last step of the TOTP algorithm: to convert the truncated hash from hex to decimal.

    According to RFC 6238, first we need to mask the most significant bit of the truncated hash
    string to 'avoid confusion about signed vs. unsigned modulo computations' (thus retaining only
    the last 31 bits of the truncated hash), but note that in this implementation, we're extracting
    the decimal otp using the array slicing method, instead of a mod computation.

    A mod computation would be: `otp_number = str(decimal_number % 10 ** num_digits)`"""

    constant: Any = constants.ConstantsNamespace()

    # apply XOR to remove the most significant bit of the hash (the most significant bit will be 0)
    decimal_number: int = int(truncated_hash, constant.BASE16) & constant.XOR_MASK

    # extract the required decimal digits to form the otp
    otp_number: str = str(decimal_number)[-num_digits:]

    return otp_number


def totp_hash_generator(secret: str, current_time: int) -> str:
    """Implementation of the TOTP algorithm, according to RFC 6238.

    :param secret: a 32-character, base32 secret
    :param current_time: current time in seconds (unix time)
    :return: a 4-byte hash string
    """

    # step 1: generate an RFC 6238 compliant hash -a hash-based message authentication code
    hmac_hash = hmac_generator(secret, current_time)

    # step 2: truncate the generated SHA1 hash with dynamic offset truncation
    truncated_hash = truncate_hash(hmac_hash)

    # step 3: convert the truncated hash from hex to decimal
    decimal_code: str = hexcode_to_otp(truncated_hash, 6)

    return decimal_code


def hex_codes_generator() -> str:
    """Generates hexadecimal codes through the TOTP algorithm, following RFC 6238.

    :return: an 8-digit hex number
    """
    secret: str = (
        secret_base32()
    )  # generate a 32 character base32 secret --for temporal testing purposes
    current_time: int = floor(time())  # unix time stamping

    hex_code: str = totp_hash_generator(secret, current_time)  # TOTP algorithm

    return hex_code
