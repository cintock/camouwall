from sys import argv
from seed_processing import PasswordValidationResultEnum, process_mnemonic
import traceback


if __name__ == '__main__':
    debug_mode = 'debug' in argv[1:]
    try:
        print('********** Seed phrase encryption application Camouwall. Version 1.1 **********')
        print('Supported seed phrases: BIP39 seed phrases from 12, 15, 18, 21, 24 words')
        extended_mnemonic = input(
            'Input seed or encrypted seed with checksum or encrypted seed without checksum: ')
        password = input('Input password: ')
        process_result = process_mnemonic(extended_mnemonic, password, print_debug=debug_mode)
        if process_result.password_validation != PasswordValidationResultEnum.ERROR:
            if process_result.password_validation == PasswordValidationResultEnum.VALID:
                print('Password is OK')
            elif process_result.password_validation == PasswordValidationResultEnum.NOT_CHECKED:
                print('It is encryption process or decryption without checksum. Password not verified')

            if process_result.seed_with_checksum is not None:
                print('You encrypted/decrypted seed with checksum: ', process_result.seed_with_checksum)
            print('You encrypted/decrypted seed without checksum: ', process_result.seed)
        else:
            print('Wrong password')
    except Exception as ex:
        print(f'Error: {ex}')
        if debug_mode:
            traceback.print_exc()
    input('Press ENTER to exit')


