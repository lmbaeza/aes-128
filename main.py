from aes import *


def AES_CBC(KEY, TXT, IV, DEBUG=False):
    key_aes = plaintext_to_hex(KEY)
    crypt = AES(key_aes)

    plaintext = plaintext_to_block(TXT, DEBUG=True)
    print(plaintext)
    ciphertext = crypt.encryptCBC(plaintext, IV)
    if DEBUG: print()
    if DEBUG: print("Cipher Text: ", ciphertext)

    txt = crypt.decryptCBC(ciphertext, IV)
    if DEBUG:  print("Decrypt : ", block_to_plaintext(txt))



KEY = "seguridad de la."
TXT = "Introduccion a la criptografia y"
#    0x00000000000000000000000000000000
IV = 0x00000000000000000000000000000000

AES_CBC(KEY, TXT, IV, DEBUG=True)

