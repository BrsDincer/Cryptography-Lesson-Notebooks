from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.backends import default_backend
import os

encryptionKEY = os.urandom(16) # 128 bits
AESEngine = Cipher(
    algorithm=algorithms.AES(encryptionKEY),
    mode=modes.ECB(),
    backend=default_backend()
)
encryptor = AESEngine.encryptor()
decryptor = AESEngine.decryptor()

message = b"0000000000000000"
print(f"LENGTH OF MESSAGE: {len(message)}\n")
# The update functions for both encryption and decryption always work on 16 bytes at a time.
## Calling update with fewer than 16 bytes produces no immediate result.
### Once 16 or more bytes are available, as many 16-byte blocks of ciphertext as possible are produced.

cipher = encryptor.update(message) + encryptor.finalize()
print(f"CIPHER LENGTH: {len(cipher.hex())}\n")
decrypted = decryptor.update(cipher) + decryptor.finalize()
print(f"PLAIN: {decrypted}\n")