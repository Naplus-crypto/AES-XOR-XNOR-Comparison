import mode_aes  # นำเข้าโมดูล aes ที่เขียนเอง

# Main entry point: interactively pick an AES variant (XOR or XNOR) and a
# cipher mode (ECB, CBC, PCBC, CFB, OFB, or CTR), then encrypt/decrypt with
# a timing + memory report.
if __name__ == "__main__":
    mode_aes.mode.run()
