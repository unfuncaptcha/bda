from Crypto.Cipher import AES
from hashlib import md5
import base64


class BDACrypto(object):
    BLOCK_SIZE: int = 16

    def __init__(self, key: str):
        self.key: str = key


    def decrypt(self, fp_data: dict) -> bytes:
        iv, ciphertext, salt = fp_data['iv'], fp_data['ct'], fp_data['s']
        salted_key = self.key.encode() + bytes.fromhex(salt)

        md5_hash_chain = [md5(salted_key).digest()]
        md5_hash_chain.extend(md5(md5_hash_chain[-1] + salted_key).digest() for _ in range(3))

        decrypted = AES.new(
            b"".join(md5_hash_chain)[:32],
            AES.MODE_CBC,
            bytes.fromhex(iv)
        ).decrypt(base64.b64decode(ciphertext))

        return self.unpad(decrypted)


    def re_encrypt(self, data: str, fp_data: dict) -> dict:
        iv, salt = fp_data['iv'], fp_data['s']
        salted_key = self.key.encode() + bytes.fromhex(salt)

        md5_hash_chain = [md5(salted_key).digest()]
        md5_hash_chain.extend(md5(md5_hash_chain[-1] + salted_key).digest() for _ in range(3))

        aes = AES.new(b"".join(md5_hash_chain)[:32], AES.MODE_CBC, bytes.fromhex(iv))
        encrypted_data = base64.b64encode(aes.encrypt(self.pad(data).encode())).decode()

        
        return {'ct': encrypted_data, 's': salt, 'iv': iv}


    @staticmethod
    def unpad(data: bytes) -> bytes:
        return data[:-data[-1]]


    @staticmethod
    def pad(data: bytes) -> bytes:
        return data + chr(BDACrypto.BLOCK_SIZE - len(data) % BDACrypto.BLOCK_SIZE) * (BDACrypto.BLOCK_SIZE - len(data) % BDACrypto.BLOCK_SIZE)
