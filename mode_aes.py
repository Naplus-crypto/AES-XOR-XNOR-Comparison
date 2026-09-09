import base64
import os

import xor_aes
import xnor_aes
import performance_test

KEY_SIZE_MAP = {'128': 16, '192': 24, '256': 32}
MODES_NEEDING_IV = {'cbc', 'pcbc', 'cfb', 'ofb', 'ctr'}
ENGINES = {'xor': xor_aes, 'xnor': xnor_aes}


def bytes2binary(byte_data):
    return ''.join(format(byte, '08b') for byte in byte_data)


class mode:
    """
    Interactive CLI for encrypting/decrypting with either AES variant
    (XOR-based or XNOR-based) in any of the six implemented modes:
    ECB, CBC, PCBC, CFB, OFB, CTR.

    Previously this only exposed three named entry points — ecb() (always
    XOR), necb() (always XNOR-ECB, confusingly named), and ctr() (always
    XOR) — so CBC/PCBC/CFB/OFB were implemented in xor_aes.py/xnor_aes.py
    but could never actually be selected or tested here. run() now asks
    for engine and mode independently so every combination is reachable.
    """

    @staticmethod
    def run():
        engine_name = input("Which AES variant do you want to use (xor, xnor)?: ").strip().lower()
        if engine_name not in ENGINES:
            print("Invalid variant selected. Please choose 'xor' or 'xnor'.")
            return

        cipher_mode = input("Which mode do you want to use (ecb, cbc, pcbc, cfb, ofb, ctr)?: ").strip().lower()
        if cipher_mode not in MODES_NEEDING_IV and cipher_mode != 'ecb':
            print("Invalid mode selected. Please choose one of: ecb, cbc, pcbc, cfb, ofb, ctr.")
            return

        aes_module = ENGINES[engine_name]
        needs_iv = cipher_mode in MODES_NEEDING_IV

        key_size = input("Enter the key size (128, 192, 256): ")
        if key_size not in KEY_SIZE_MAP:
            print("Invalid key size selected. Please choose '128', '192' or '256'.")
            return

        input_type = input("Do you want to input data as (s)tring or (h)ex?: ").lower()
        if input_type == 's':
            plain_text = input("Enter the plaintext message: ").encode('utf-8')
        elif input_type == 'h':
            plain_text_hex = input("Enter the plaintext message (hex): ")
            plain_text = bytes.fromhex(plain_text_hex)
            print("Plain Text (binary):", bytes2binary(plain_text))
        else:
            print("Invalid input type selected. Please choose 's' for string or 'h' for hex.")
            return

        key = os.urandom(KEY_SIZE_MAP[key_size])
        key_input = input("Enter the Key (hex or leave blank to use random key): ")
        if key_input:
            if all(c in '0123456789abcdefABCDEF' for c in key_input):
                key = bytes.fromhex(key_input)
                print("Key (binary):", bytes2binary(key))
            else:
                key = base64.b64decode(key_input)
        print("Key (base64):", base64.b64encode(key).decode('utf-8'))

        iv = None
        if needs_iv:
            iv = os.urandom(16)
            iv_input = input("Enter the IV (hex or leave blank to use random IV): ")
            if iv_input:
                if all(c in '0123456789abcdefABCDEF' for c in iv_input):
                    iv = bytes.fromhex(iv_input)
                else:
                    iv = base64.b64decode(iv_input)
            print("IV (base64):", base64.b64encode(iv).decode('utf-8'))

        aes_instance = aes_module.AES(key)
        encrypt_fn = getattr(aes_instance, f'encrypt_{cipher_mode}')
        decrypt_fn = getattr(aes_instance, f'decrypt_{cipher_mode}')

        enc_args = (plain_text, iv) if needs_iv else (plain_text,)
        cipher_text = encrypt_fn(*enc_args)
        print("Cipher Text (base64):", base64.b64encode(cipher_text).decode('utf-8'))
        print("Cipher Text (hex):", cipher_text.hex())
        print("Cipher Text (bytes):", cipher_text)
        print("Cipher Text (binary):", bytes2binary(cipher_text))

        dec_args = (cipher_text, iv) if needs_iv else (cipher_text,)
        decrypted_text = decrypt_fn(*dec_args)
        if input_type == 's':
            print("Decrypted Text:", decrypted_text.decode('utf-8'))
        elif input_type == 'h':
            print("Decrypted Text:", decrypted_text.hex())

        performance_test.pt.run_test(engine_name, cipher_mode, key, plain_text, iv)
