from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms,modes

class Person:
    def __init__(self, name):
        self.name = name
        self.seq = 0
        self.dh_private_key = None
        self.dh_public_key = None
        self.dh_peer_public_key = None
        self.aes_key = None
        self.cert = None
        self.kr = None
        self.ca_ku = None

        # Load certificate
        with open(f'certificates/{self.name}_CERT.pem', 'rb') as cert_file:
            pem_data = cert_file.read()
            self.cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            self.ku = self.cert.public_key()

        # Load private key
        with open(f'certificates/{self.name}_KR.pem', 'rb') as private_key_file:
            pem_data = private_key_file.read()
            self.kr = serialization.load_pem_private_key(
                pem_data,
                password=None,
                backend=default_backend()
            )

        # Load CA's public key
        with open('certificates/CA_KU.pem', 'rb') as ca_public_key_file:
            pem_data = ca_public_key_file.read()
            self.ca_ku = serialization.load_pem_public_key(
                pem_data,
                backend=default_backend()
            )

        print(f'{name} initialized')

    def generate_dh_public_key(self):
        print('Generating DH public/private key pair')
        self.dh_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.dh_public_key = self.dh_private_key.public_key()

        print('DH Public Key:')
        print(self.dh_public_key)

        print('Signing DH public key with private key')
        signature = self.kr.sign(
            self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            ec.ECDSA(hashes.SHA256())  # Specify the hash algorithm here
        )

        return self.dh_public_key, signature

    def set_dh_peer_public_key(self, dh_peer_public_key, signature, peer_cert):
        print('received DH public key from peer')
        self.dh_peer_public_key = dh_peer_public_key

        # Authenticate peer by verifying his certificate
        print('verifying certificate of peer')
        self.ca_ku.verify(
             peer_cert.signature,
             peer_cert.tbs_certificate_bytes,
             ec.ECDSA(hashes.SHA256())
        )
        print('verifiying signature of public key')
        peer_cert.public_key().verify(
             signature,
             dh_peer_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
             ),
             ec.ECDSA(hashes.SHA256())
         )
        print("donedone")
    def calculate_symmetric_key(self):
        try:
            if self.dh_private_key is None or self.dh_peer_public_key is None:
                raise ValueError('DH private key or peer public key is not set.')

            print('Calculating symmetric key')
            secret_symmetric_key = self.dh_private_key.exchange(ec.ECDH(), self.dh_peer_public_key)
            self.aes_key = secret_symmetric_key[:16]  # Use first 16 bytes as AES key
            print(f'{self.name}: Symmetric key generated')
            print('Shared Secret (AES Key):')
            print(self.aes_key.hex())
        except Exception as e:
            print(f'Error calculating symmetric key: {e}')

    def get_certificate(self):
        return self.cert

    def encrypt(self, message):
        try:
            if self.aes_key is None:
                raise ValueError('AES key is not set.')

            print('Encrypting message...')
            iv = ec.generate_private_key(ec.SECP256R1(), default_backend()).exchange(ec.ECDH(), self.dh_peer_public_key)
            cipher = Cipher(
                algorithms.AES(self.aes_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ct = encryptor.update(message) + encryptor.finalize()
            print('Encryption complete')
            print('Initialization Vector (IV):')
            print(iv.hex())
            print('Authentication Tag:')
            print(encryptor.tag.hex())
            return ct, iv, encryptor.tag, self.cert
        except Exception as e:
            print(f'Error encrypting message: {e}')
            return None, None, None, None

    def decrypt(self, ct, iv, tag, peer_cert):
        try:
            if self.aes_key is None:
                raise ValueError('AES key is not set.')

            print('Decrypting message...')
            cipher = Cipher(
                algorithms.AES(self.aes_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ct) + decryptor.finalize()

            print('Verifying peer certificate for decryption')
            self.ca_ku.verify(
                peer_cert.signature,
                peer_cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )

            return decrypted
        except Exception as e:
            print(f'Error decrypting message: {e}')
            return None

    def sign_ack(self, message):
        try:
            if self.kr is None:
                raise ValueError('Private key is not set.')

            print('Signing acknowledgment...')
            signature = self.kr.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
            print('Signed Message:')
            print(signature.hex())
            return signature, self.ku
        except Exception as e:
            print(f'Error signing acknowledgment: {e}')
            return None, None

    def verify_ack_signature(self, message, signature, peer_ku):
        try:
            if peer_ku is None:
                raise ValueError('Peer key is not set.')

            print('Verifying acknowledgment signature...')
            peer_ku.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            print(f'{self.name} received an acknowledgment from the peer.')
        except Exception as e:
            print(f'Error verifying acknowledgment signature: {e}')
