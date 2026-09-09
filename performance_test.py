import time
import tracemalloc

import xor_aes
import xnor_aes

MODES_NEEDING_IV = {'cbc', 'pcbc', 'cfb', 'ofb', 'ctr'}
ALL_MODES = ['ecb', 'cbc', 'pcbc', 'cfb', 'ofb', 'ctr']
ENGINES = {'xor': xor_aes, 'xnor': xnor_aes}


def print_message_info(message, message_type):
    message_size_kb = len(message) / 1024
    message_length = len(message)
    print(f"{message_type} size: {message_size_kb:.6f} KB")
    print(f"{message_type} bytes: {message_length} bytes")


class pt:

    @staticmethod
    def run_test(engine_name, mode, key, plain_text, iv=None, verbose=True):
        """
        Times and memory-profiles a full encrypt+decrypt round trip, then
        encryption alone, then decryption alone, for the given engine
        ('xor' or 'xnor') and cipher mode. Replaces the old ecb_test /
        necb_test / ctr_test functions, which duplicated this logic three
        times and only covered ECB (both engines) and CTR (XOR only) —
        CBC/PCBC/CFB/OFB were implemented in xor_aes.py/xnor_aes.py but
        were never actually exercised by any experiment.
        """
        aes_module = ENGINES[engine_name]
        aes_instance = aes_module.AES(key)
        encrypt_fn = getattr(aes_instance, f'encrypt_{mode}')
        decrypt_fn = getattr(aes_instance, f'decrypt_{mode}')
        needs_iv = mode in MODES_NEEDING_IV
        enc_args = (plain_text, iv) if needs_iv else (plain_text,)

        # Full round trip
        tracemalloc.start()
        start_time = time.time()
        cipher_text = encrypt_fn(*enc_args)
        dec_args = (cipher_text, iv) if needs_iv else (cipher_text,)
        decrypted_text = decrypt_fn(*dec_args)
        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Encryption only
        tracemalloc.start()
        start_etime = time.time()
        cipher_text = encrypt_fn(*enc_args)
        end_etime = time.time()
        ecurrent, epeak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Decryption only
        dec_args = (cipher_text, iv) if needs_iv else (cipher_text,)
        tracemalloc.start()
        start_dtime = time.time()
        decrypted_text = decrypt_fn(*dec_args)
        end_dtime = time.time()
        dcurrent, dpeak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        result = {
            'engine': engine_name,
            'mode': mode,
            'round_trip_time': end_time - start_time,
            'current_mem_mb': current / 10**6,
            'peak_mem_mb': peak / 10**6,
            'encrypt_time': end_etime - start_etime,
            'encrypt_current_mem_mb': ecurrent / 10**6,
            'encrypt_peak_mem_mb': epeak / 10**6,
            'decrypt_time': end_dtime - start_dtime,
            'decrypt_current_mem_mb': dcurrent / 10**6,
            'decrypt_peak_mem_mb': dpeak / 10**6,
            'correct': plain_text == decrypted_text,
        }

        if verbose:
            print(f"[{engine_name.upper()}-AES / {mode.upper()}]")
            print(f"Execution time: {result['round_trip_time']} seconds")
            print(f"Current memory usage: {result['current_mem_mb']} MB")
            print(f"Peak memory usage: {result['peak_mem_mb']} MB")
            print(f"Encrypted time: {result['encrypt_time']} seconds")
            print(f"Current encrypted memory usage: {result['encrypt_current_mem_mb']} MB")
            print(f"Peak encrypted memory usage: {result['encrypt_peak_mem_mb']} MB")
            print(f"Decrypted time: {result['decrypt_time']} seconds")
            print(f"Current decrypted memory usage: {result['decrypt_current_mem_mb']} MB")
            print(f"Peak decrypted memory usage: {result['decrypt_peak_mem_mb']} MB")
            print("Decryption successful:", result['correct'])
            aes_instance.display_key_info()
            print_message_info(plain_text, "Plain Text")

        return result

    # Thin wrappers kept for backwards compatibility with existing call
    # sites (mode_aes.py used to call these three by name).
    @staticmethod
    def ecb_test(key, plain_text):
        return pt.run_test('xor', 'ecb', key, plain_text)

    @staticmethod
    def necb_test(key, plain_text):
        return pt.run_test('xnor', 'ecb', key, plain_text)

    @staticmethod
    def ctr_test(key, plain_text, iv):
        return pt.run_test('xor', 'ctr', key, plain_text, iv)


def run_all_modes(key_sizes=(16,), message_sizes_kb=(4, 8, 16), modes=ALL_MODES):
    """
    Benchmarks every (engine, mode) combination across a range of message
    sizes, returning a flat list of result dicts. This is what the README
    results table is generated from.
    """
    import os
    all_results = []
    for engine_name in ENGINES:
        for mode in modes:
            for size_kb in message_sizes_kb:
                for key_size in key_sizes:
                    key = os.urandom(key_size)
                    plain_text = os.urandom(size_kb * 1024)
                    iv = os.urandom(16) if mode in MODES_NEEDING_IV else None
                    result = pt.run_test(engine_name, mode, key, plain_text, iv, verbose=False)
                    result['message_size_kb'] = size_kb
                    result['key_size_bytes'] = key_size
                    all_results.append(result)
    return all_results


if __name__ == "__main__":
    results = run_all_modes()
    header = f"{'Engine':<6} {'Mode':<6} {'Size(KB)':>9} {'Enc time(s)':>12} {'Dec time(s)':>12} {'Peak mem(MB)':>13} {'OK':>4}"
    print(header)
    print('-' * len(header))
    for r in results:
        print(f"{r['engine']:<6} {r['mode']:<6} {r['message_size_kb']:>9} "
              f"{r['encrypt_time']:>12.6f} {r['decrypt_time']:>12.6f} "
              f"{r['peak_mem_mb']:>13.4f} {str(r['correct']):>4}")
