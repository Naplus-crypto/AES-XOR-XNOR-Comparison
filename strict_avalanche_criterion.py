"""
Strict Avalanche Criterion (SAC) test for the XOR-based and XNOR-based
AES-128 implementations in this project.

SAC says: flipping a single input bit should flip, on average, half of the
output bits. For an n-bit ciphertext the ideal average number of changed
bits is n/2, with 0% relative error.
"""
import os
import matplotlib.pyplot as plt

import xor_aes
import xnor_aes

MODES_NEEDING_IV = {'cbc', 'pcbc', 'cfb', 'ofb', 'ctr'}
ALL_MODES = ['ecb', 'cbc', 'pcbc', 'cfb', 'ofb', 'ctr']

# In CFB/OFB/CTR the plaintext is only ever XORed with a keystream that is
# generated from the key and IV/nonce alone — the plaintext itself never
# passes through the AES round function. So flipping a plaintext bit in a
# single-block test only ever flips the one corresponding ciphertext bit
# (a "keystream is a one-time pad" property, not a diffusion bug), and SAC
# tells us nothing about the cipher's diffusion if we flip the plaintext
# there. For those modes we instead flip bits of the IV/nonce, which *does*
# feed the round function directly, so SAC measures what it's meant to.
MODES_FLIPPING_IV = {'cfb', 'ofb', 'ctr'}


def bytes_to_bitstring(byte_data):
    return ''.join(f'{byte:08b}' for byte in byte_data)


def count_different_bits(bitstring1, bitstring2):
    return sum(bit1 != bit2 for bit1, bit2 in zip(bitstring1, bitstring2))


def mean(values):
    return sum(values) / len(values)


def standard_deviation(values, mean_value):
    variance = sum((x - mean_value) ** 2 for x in values) / len(values)
    return variance ** 0.5


def rms_error(values, ideal_value):
    """
    Root-mean-square error of `values` around the ideal SAC value
    (half of the total output bits).

    BUGFIX: the previous version computed sqrt(sum((x-64)**2)) and only
    divided by n *after* taking the square root, i.e. sqrt(sum) / n instead
    of sqrt(sum / n). That understates the true RMSE by roughly a factor of
    sqrt(n), and it also hardcoded 64 as the ideal value, which is only
    correct for a 128-bit (16-byte) block — modes that pad the plaintext
    (CBC/PCBC) produce longer ciphertexts, so the ideal value is different.
    """
    variance = sum((x - ideal_value) ** 2 for x in values) / len(values)
    return variance ** 0.5


def encrypt_with(aes_module, mode, key, data, iv):
    """Dispatch to the right encrypt_<mode> method on an AES instance."""
    aes = aes_module.AES(key)
    if mode in MODES_NEEDING_IV:
        return getattr(aes, f'encrypt_{mode}')(data, iv)
    return aes.encrypt_ecb(data)


def test_sac(aes_module, mode, original_data, key, iv):
    """
    Runs the SAC test: flips every bit of the relevant input one at a time,
    re-encrypts, and measures how many output bits changed relative to the
    unmodified ciphertext. For ECB/CBC/PCBC the plaintext is flipped; for
    CFB/OFB/CTR the IV/nonce is flipped instead (see MODES_FLIPPING_IV).
    """
    flip_iv = mode in MODES_FLIPPING_IV
    flip_target = bytearray(iv if flip_iv else original_data)

    original_encrypted = encrypt_with(aes_module, mode, key, original_data, iv)
    original_encrypted_bits = bytes_to_bitstring(original_encrypted)
    total_output_bits = len(original_encrypted_bits)
    ideal_value = total_output_bits / 2

    bit_changes = []
    for i in range(len(flip_target) * 8):
        modified_target = bytearray(flip_target)
        byte_index = i // 8
        bit_index = i % 8
        modified_target[byte_index] ^= 1 << bit_index

        if flip_iv:
            modified_encrypted = encrypt_with(aes_module, mode, key, original_data, bytes(modified_target))
        else:
            modified_encrypted = encrypt_with(aes_module, mode, key, bytes(modified_target), iv)
        modified_encrypted_bits = bytes_to_bitstring(modified_encrypted)

        different_bits = count_different_bits(original_encrypted_bits, modified_encrypted_bits)
        bit_changes.append(different_bits)

    avg_changes = mean(bit_changes)
    std_dev_changes = standard_deviation(bit_changes, avg_changes)
    rms_error_changes = rms_error(bit_changes, ideal_value)

    return {
        'bit_changes': bit_changes,
        'avg': avg_changes,
        'std_dev': std_dev_changes,
        'rmse': rms_error_changes,
        'ideal': ideal_value,
        'total_output_bits': total_output_bits,
        'avg_pct': avg_changes / total_output_bits * 100,
    }


def run_all_modes(key=None, original_data=None, iv=None, modes=ALL_MODES):
    """
    Runs the SAC test for both AES variants across every cipher mode and
    returns a results dict keyed by (engine_name, mode).
    """
    key = key if key is not None else os.urandom(16)
    original_data = original_data if original_data is not None else os.urandom(16)
    iv = iv if iv is not None else os.urandom(16)

    engines = {'XOR-AES': xor_aes, 'XNOR-AES': xnor_aes}
    results = {}
    for engine_name, module in engines.items():
        for mode in modes:
            results[(engine_name, mode)] = test_sac(module, mode, original_data, key, iv)
    return results, key, original_data, iv


def print_summary(results):
    header = f"{'Engine':<10} {'Mode':<6} {'Avg bits changed':>18} {'Avg %':>8} {'Std dev':>10} {'RMSE':>8} {'Ideal':>8}"
    print(header)
    print('-' * len(header))
    for (engine_name, mode), r in results.items():
        print(f"{engine_name:<10} {mode:<6} {r['avg']:>18.2f} {r['avg_pct']:>7.2f}% "
              f"{r['std_dev']:>10.3f} {r['rmse']:>8.3f} {r['ideal']:>8.1f}")


def plot_summary(results, modes=ALL_MODES, save_path='sac_results.png'):
    engines = ['XOR-AES', 'XNOR-AES']
    x = range(len(modes))
    width = 0.35

    plt.figure(figsize=(10, 5))
    for offset, engine_name in zip((-width / 2, width / 2), engines):
        values = [results[(engine_name, mode)]['avg_pct'] for mode in modes]
        plt.bar([xi + offset for xi in x], values, width=width, label=engine_name)

    plt.axhline(50, color='gray', linestyle='--', linewidth=1, label='Ideal (50%)')
    plt.xticks(list(x), [m.upper() for m in modes])
    plt.ylabel('Average bits changed (%)')
    plt.title('Strict Avalanche Criterion by mode')
    plt.legend()
    plt.tight_layout()
    plt.savefig(save_path)
    plt.show()


if __name__ == "__main__":
    print("Running SAC test across all modes for XOR-AES and XNOR-AES...")
    results, key, original_data, iv = run_all_modes()
    print_summary(results)
    plot_summary(results)
