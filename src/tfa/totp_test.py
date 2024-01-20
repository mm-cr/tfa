"""
Test Module. Implements test cases for the TOTP algorithm according the RFC 6238.
"""

from typing import Any

import pytest

import constants
from code_generator import hexcode_to_otp, totp_hash_generator

test_data = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]

constant: Any = constants.TestConstantsNamespace()


@pytest.mark.parametrize(("timestamp", "expected_code"), test_data)
def test_totp_generator(timestamp, expected_code):
    """Test case for the TOTP, using the test data presented in RFC 6238"""

    # function call
    truncated_hash = totp_hash_generator(constant.TEST_SECRET, timestamp)
    actual_code = hexcode_to_otp(truncated_hash, constant.TEST_NUM_DIGITS)

    # assertion
    assert actual_code == expected_code, (
        "codes do not match - actual: " + actual_code + ", expected: " + expected_code
    )
