import dataclasses
import hashlib
from enum import Enum
from typing import Optional

import bip39
import pbkdf2

SALT = b'salt-hidden-seed'
ENCRYPTION_ITERATIONS = 100000
CHECKSUM_LENGTH_BYTES = 2


class PasswordValidationResultEnum(Enum):
    VALID = 'valid'
    ERROR = 'error'
    NOT_CHECKED = 'not_checked'


@dataclasses.dataclass(slots=True)
class SeedAndChecksum:
    seed: str
    check_sum: Optional[int]


@dataclasses.dataclass(slots=True)
class SeedProcessionResult:
    seed: str
    seed_with_checksum: Optional[str]
    checksum: Optional[int]
    password_validation: PasswordValidationResultEnum


def get_key_number_from_password(password: str, key_length_in_bytes: int) -> int:
    key_calc = pbkdf2.PBKDF2(password, SALT, iterations=ENCRYPTION_ITERATIONS, digestmodule=hashlib.sha256)
    password_hash_bytes = key_calc.read(key_length_in_bytes)

    password_hash_int = int.from_bytes(password_hash_bytes, byteorder='big')

    return password_hash_int


def split_mnemonic_and_checksum(seed_with_checksum: str) -> SeedAndChecksum:
    start_index = seed_with_checksum.find("*")
    if start_index >= 0:
        end_index = seed_with_checksum.rfind("*")
        if end_index == start_index:
            raise Exception('Invalid extended seed format')

        check_sum_str = seed_with_checksum[start_index + 1:end_index]
        check_sum_int = int(check_sum_str, 16)

        only_seed_string = seed_with_checksum[:start_index].strip()

        result = SeedAndChecksum(
            seed=only_seed_string,
            check_sum=check_sum_int
        )
    else:
        result = SeedAndChecksum(
            seed=seed_with_checksum,
            check_sum=None
        )

    return result


def get_checksum_from_bytes(seed_bytes: bytes) -> int:
    check_sum_bytes = hashlib.sha256(seed_bytes).digest()[-CHECKSUM_LENGTH_BYTES:]
    check_sum = int.from_bytes(check_sum_bytes, byteorder='big')
    return check_sum


def process_mnemonic(
        mnemonic_with_or_without_checksum: str,
        password: str,
        print_debug: bool = False
) -> SeedProcessionResult:
    mnemonic_and_checksum = split_mnemonic_and_checksum(mnemonic_with_or_without_checksum)
    can_check_password: bool = mnemonic_and_checksum.check_sum is not None
    mnemonic_bytes = bip39.decode_phrase(mnemonic_and_checksum.seed)
    source_checksum: Optional[int] = None
    expected_checksum: Optional[int] = None
    if mnemonic_and_checksum.check_sum is None:
        source_checksum = get_checksum_from_bytes(mnemonic_bytes)
    else:
        expected_checksum = mnemonic_and_checksum.check_sum

    entropy_length_in_bytes = len(mnemonic_bytes)
    mnemonic_number_int = int.from_bytes(mnemonic_bytes, byteorder='big')

    if print_debug:
        if source_checksum is not None:
            print('source check sum          ',  hex(source_checksum))

    encryption_key: int = get_key_number_from_password(password, entropy_length_in_bytes)

    if print_debug:
        print('encryption key            ', hex(encryption_key))
        print('orig mnemonic number      ', hex(mnemonic_number_int))

    encrypted_mnemonic_int = mnemonic_number_int ^ encryption_key

    if print_debug:
        print('processed mnemonic number ', hex(encrypted_mnemonic_int))

    encrypted_mnemonic_bytes = encrypted_mnemonic_int.to_bytes(entropy_length_in_bytes, byteorder='big')

    password_validation_result = PasswordValidationResultEnum.NOT_CHECKED
    if can_check_password:
        processed_checksum = get_checksum_from_bytes(encrypted_mnemonic_bytes)
        if expected_checksum == processed_checksum:
            password_validation_result = PasswordValidationResultEnum.VALID
        else:
            password_validation_result = PasswordValidationResultEnum.ERROR

    processed_seed: Optional[str] = None
    processed_seed_with_checksum: Optional[str] = None
    if password_validation_result != PasswordValidationResultEnum.ERROR:
        processed_seed = bip39.encode_bytes(encrypted_mnemonic_bytes)

        if source_checksum is not None:
            processed_seed_with_checksum = processed_seed + ' *{check_sum:x}*'.format(check_sum=source_checksum)

    return SeedProcessionResult(
        seed=processed_seed,
        seed_with_checksum=processed_seed_with_checksum,
        checksum=source_checksum,
        password_validation=password_validation_result
    )
