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


def AES_ECB(KEY, TXT, DEBUG=False):
    key_aes = plaintext_to_hex(KEY)
    crypt = AES(key_aes)

    plaintext = plaintext_to_block(TXT, DEBUG=True)
    print(plaintext)

    ciphertext = crypt.encryptECB(plaintext)

    print(ciphertext)

    if DEBUG: print()
    if DEBUG: print("Cipher Text: ", ciphertext)
    
    ans = []
    for x in ciphertext:
        txt = crypt.decryptECB(int(x, 16))
        ans.append(txt)
    
    if DEBUG:  print("Decrypt : ", block_to_plaintext(ans))


# CBC Mode - Sample

KEY = "seguridad de la."
TXT = "Introduccion a la criptografia y"
#    0x00000000000000000000000000000000
IV = 0x00000000000000000000000000000000

AES_CBC(KEY, TXT, IV, DEBUG=True)

# ECB Mode - Sample

# KEY = "seguridad de la."
# TXT = "Introduccion a la criptografia y"
# AES_ECB(KEY, TXT,DEBUG=True)

