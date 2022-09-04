"""
Take home challenge solution. Please refer to the documentation 'TakeHomeChallenge_Marlon_Mata.pdf'
for details and solution analysis.
"""

from hashlib import sha1
from hmac import new as new_hmac
from math import floor
from os.path import exists
from secrets import choice
from shelve import open as open_shelf
from time import time
from typing import Any

import constants


def prettify_hex(hex_str: str) -> str:
    """Makes a hex number more human-readable by adding the '0x' prefix and capitalizing letters.
    For example, from 'a431e45b' to '0xA431E45B'.

    :param hex_str: truncated hexadecimal string to be formatted
    :return: formatted hexadecimal string
    """
    return "0x" + hex_str.upper()


def hex_censor(hex_code: str) -> bool:
    """Checks if the parameter "hex_code" is an odd-looking code or hexspeak code present in the
    banned codes' dictionary (a txt file with the banned codes on it.)

    :param hex_code: hexadecimal string to be checked
    :return: True if hex_code is in the banned codes' dictionary, False otherwise
    """
    banned_code: bool = False

    if exists("banned_codes_dict.txt"):
        try:
            with open("banned_codes_dict.txt", encoding="utf-8") as file:
                if hex_code.lower() in file.read().lower():
                    banned_code = True
        except PermissionError:
            print("Permission Error trying to access the file 'banned_codes_dict.txt'")

    else:
        # if the dict doesn't exist, created, to be able to add banned hex codes to the file
        try:
            with open("banned_codes_dict.txt", "x", encoding="utf-8") as file:
                file.close()
        except PermissionError:
            print("Permission Error trying to create the file 'banned_codes_dict.txt'")

    return banned_code


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


def hmac_generator(secret: str) -> str:
    """HMAC-SHA-1 algorithm implementation (for Hash computation) to produce a message
    authentication code. It generates a 160-bit hash value (the message digest). If we could use
    SHA256 for the hash generation, it would generate a more secure (256-bit) hmac. We're using
    SHA1 to avoid future compatibility issues with current OTP apps.

    :param secret: a 32-character, base32 secret
    :return: a 160-bit hash string (a message digest from the HMAC-SHA-1 algorithm)
    """
    constant: Any = constants.ConstantsNamespace()

    current_time_in_seconds = floor(time())  # we use time.time() for unix time stamping

    try:
        # time_counter will be our time-base counter -the moving factor-
        time_counter = floor(current_time_in_seconds / constant.TIME_STEP_IN_SECONDS)

    except ZeroDivisionError:
        time_counter = floor(current_time_in_seconds)

    # Convert to bytes the secret and time counter to use the new() function of the hmac module to
    #   generate the hash
    secret_in_bytes: bytes = bytes(secret, "utf-8")
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


def totp_hash_generator(secret: str) -> str:
    """Implementation of the TOTP algorithm, according to RFC 6238.

    :param secret: a 32-character, base32 secret
    :return: a 4-byte hash string
    """
    # generates an RFC 6238 compliant hash -a hash-based message authentication code
    hmac_hash = hmac_generator(secret)

    # we truncate the generated SHA1 hash with dynamic offset truncation
    truncated_hash = truncate_hash(hmac_hash)

    return truncated_hash


def get_secret() -> str:
    """Retrieves the secret from the database (a shelf.)

    :return: a 32-character, base32 secret
    """
    secret: str = ""

    # We use the "Shelve" Module to create a file and stores dictionary entries in it
    try:
        with open_shelf("db") as db_file:
            secret = str(db_file.get("secret"))

            # If there is no secret in our database, generate one, then store the secret in the db
            if secret is None:
                secret = secret_base32()
                db_file["secret"] = secret

    except PermissionError:
        print("Error trying to access the file 'db.dat'")
        secret = secret_base32()

    finally:
        db_file.close()

    return secret


def hex_codes_generator() -> str:
    """Generates hexadecimal codes through the TOTP algorithm, following RFC 6238.

    :return: an 8-digit hex number
    """
    bad_code: bool = True
    hex_code: str = ""
    secret: str = get_secret()

    while bad_code:
        hex_code = totp_hash_generator(secret)
        bad_code = hex_censor(hex_code)

    return hex_code


def main():
    """Main function, creates a code and prints it on the console."""
    code: str = hex_codes_generator()
    print(prettify_hex(code))


if __name__ == "__main__":
    main()
