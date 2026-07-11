import base64
import os
import xor_aes, xnor_aes  # นำเข้าโมดูล aes ที่เขียนเอง
import performance_test  #นำเข้าโมดูลทดสอบที่เขียนเอง

def bytes2binary(byte_data):
    return ''.join(format(byte, '08b') for byte in byte_data)

class mode:
    
    @staticmethod
    def ctr():
        key_size = input("Enter the key size (128, 192, 256): ")

        key_size_map = {
            '128': 16,
            '192': 24,
            '256': 32
        }

        if key_size not in key_size_map:
            print("Invalid key size selected. Please choose '128', '192' or '256'.")
            exit()
        
        input_type = input("Do you want to input data as (s)tring or (h)ex?: ").lower()

        if input_type == 's':
            plain_text = input("Enter the plaintext message: ").encode('utf-8')
        elif input_type == 'h':
            plain_text_hex = input("Enter the plaintext message (hex): ")
            plain_text = bytes.fromhex(plain_text_hex)
        else:
            print("Invalid input type selected. Please choose 's' for string or 'h' for hex.")
            exit()

        key = os.urandom(key_size_map[key_size])  # AES key based on selected size
        iv = os.urandom(16)  # 128-bit IV
        key_input = input("Enter the Key (hex or leave blank to use random key): ")
        if key_input:
            if all(c in '0123456789abcdefABCDEF' for c in key_input):  # Hex input
                key = bytes.fromhex(key_input)
            else:
                key = base64.b64decode(key_input)
        print("Key (base64):", base64.b64encode(key).decode('utf-8'))
        print("Key (bytes):", key)             
        
        iv_input = input("Enter the IV (hex or leave blank to use random IV): ")
        if iv_input:
            if all(c in '0123456789abcdefABCDEF' for c in iv_input):  # Hex input
                iv = bytes.fromhex(iv_input)
            else:  
                iv = base64.b64decode(iv_input)
        print("IV (base64):", base64.b64encode(iv).decode('utf-8'))
        print("IV (bytes):", iv)
             
        cipher_text = xor_aes.AES(key).encrypt_ctr(plain_text, iv)
        print("Cipher Text (base64):", base64.b64encode(cipher_text).decode('utf-8'))
        print("Cipher Text (hex):", cipher_text.hex())
        
        decrypted_text = xor_aes.AES(key).decrypt_ctr(cipher_text, iv)
        if input_type == 's':
        	print("Decrypted Text:", decrypted_text.decode('utf-8'))
        elif input_type == 'h':
        	print("Decrypted Text:", decrypted_text.hex())
        
        # Perform performance test
        performance_test.pt.ctr_test(key, plain_text, iv)
    
    
    @staticmethod
    def necb():
        key_size = input("Enter the key size (128, 192, 256): ")

        key_size_map = {
            '128': 16,
            '192': 24,
            '256': 32
        }

        if key_size not in key_size_map:
            print("Invalid key size selected. Please choose '128', '192' or '256'.")
            exit()
        
        input_type = input("Do you want to input data as (s)tring or (h)ex?: ").lower()

        if input_type == 's':
            plain_text = input("Enter the plaintext message: ").encode('utf-8')
        elif input_type == 'h':
            plain_text_hex = input("Enter the plaintext message (hex): ")
            plain_text = bytes.fromhex(plain_text_hex)
            print("Plain Text (binary):", bytes2binary(plain_text))
        else:
            print("Invalid input type selected. Please choose 's' for string or 'h' for hex.")
            exit()

        key = os.urandom(key_size_map[key_size])  # AES key based on selected size
        key_input = input("Enter the Key (hex or leave blank to use random key): ")

        if key_input:
            if all(c in '0123456789abcdefABCDEF' for c in key_input):  # Hex input
                key = bytes.fromhex(key_input)
                print("Key (binary):", bytes2binary(key))
            else:
                key = base64.b64decode(key_input)

        print("Key (base64):", base64.b64encode(key).decode('utf-8'))

        cipher_text = xnor_aes.AES(key).encrypt_ecb(plain_text)
        print("Cipher Text (base64):", base64.b64encode(cipher_text).decode('utf-8'))
        print("Cipher Text (hex):", cipher_text.hex())
        print("Cipher Text (bytes):", cipher_text)
        print("Cipher Text (binary):", bytes2binary(cipher_text))

        decrypted_text = xnor_aes.AES(key).decrypt_ecb(cipher_text)
        if input_type == 's':
            print("Decrypted Text:", decrypted_text.decode('utf-8'))
        elif input_type == 'h':
            print("Decrypted Text:", decrypted_text.hex())

        # Perform performance test
        performance_test.pt.necb_test(key, plain_text)
 
    
    @staticmethod
    def ecb():
        key_size = input("Enter the key size (128, 192, 256): ")

        key_size_map = {
            '128': 16,
            '192': 24,
            '256': 32
        }

        if key_size not in key_size_map:
            print("Invalid key size selected. Please choose '128', '192' or '256'.")
            exit()
        
        input_type = input("Do you want to input data as (s)tring or (h)ex?: ").lower()

        if input_type == 's':
            plain_text = input("Enter the plaintext message: ").encode('utf-8')
        elif input_type == 'h':
            plain_text_hex = input("Enter the plaintext message (hex): ")
            plain_text = bytes.fromhex(plain_text_hex)
            print("Plain Text (binary):", bytes2binary(plain_text))
        else:
            print("Invalid input type selected. Please choose 's' for string or 'h' for hex.")
            exit()

        key = os.urandom(key_size_map[key_size])  # AES key based on selected size
        key_input = input("Enter the Key (hex or leave blank to use random key): ")

        if key_input:
            if all(c in '0123456789abcdefABCDEF' for c in key_input):  # Hex input
                key = bytes.fromhex(key_input)
                print("Key (binary):", bytes2binary(key))
            else:
                key = base64.b64decode(key_input)

        print("Key (base64):", base64.b64encode(key).decode('utf-8'))

        cipher_text = xor_aes.AES(key).encrypt_ecb(plain_text)
        print("Cipher Text (base64):", base64.b64encode(cipher_text).decode('utf-8'))
        print("Cipher Text (hex):", cipher_text.hex())
        print("Cipher Text (bytes):", cipher_text)
        print("Cipher Text (binary):", bytes2binary(cipher_text))

        decrypted_text = xor_aes.AES(key).decrypt_ecb(cipher_text)
        if input_type == 's':
            print("Decrypted Text:", decrypted_text.decode('utf-8'))
        elif input_type == 'h':
            print("Decrypted Text:", decrypted_text.hex())

        # Perform performance test
        performance_test.pt.ecb_test(key, plain_text)
       
