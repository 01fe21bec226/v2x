import socket
import json
import os
from cryptography import x509
from person import Person
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms,modes
from certificates import create_certificates, create_pub_priv_key_pair
def serialize_certificate(cert):
    # Serialize the certificate to PEM format
    pem_data = cert.public_bytes(encoding=serialization.Encoding.PEM)
    # Convert the PEM data to a hexadecimal string
    hex_data = pem_data.hex()
    return hex_data
def deserialize_ec_public_key(hex_data):
    # Convert hexadecimal string back to binary data
    pem_data = bytes.fromhex(hex_data)
    # Deserialize the binary data into an _EllipticCurvePublicKey object
    public_key = serialization.load_pem_public_key(pem_data, default_backend())
    return public_key

def send_message(conn, message):
    conn.sendall(json.dumps(message).encode('utf-8'))

def receive_message(conn):
    data = conn.recv(4096).decode('utf-8')
    print("Received data:", data)  # Add this line to print received data
    return json.loads(data)

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8085))
    server_socket.listen()

    print("Node 1 is listening for incoming connections...")

    conn, addr = server_socket.accept()

    with conn:
        print(f"Connected to Node 2 at {addr}")

        try:
            node1 = Person('Node 1')
            node1_dh_public_key, node1_dh_signature = node1.generate_dh_public_key()
            """
            print('DH Peer Public Key:')
            print(node1_dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode())
            """
            message = {
                'dh_public_key': node1_dh_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                'dh_signature': node1_dh_signature.hex()
            }
            send_message(conn, json.dumps(message))

            response = receive_message(conn)
            print("Received data:", response)
            
            if response:
                response = json.loads(response)
                node2_dh_public_key = serialization.load_pem_public_key(
                    response['dh_public_key'].encode(),
                    backend=None
                )
                node2_dh_signature = bytes.fromhex(response['dh_signature'])

                print("Node 2's DH public key signature verified successfully.")
                with open('certificates/Node 2_CERT.pem', 'rb') as cert_file:
                    node2_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

                node1.set_dh_peer_public_key(dh_peer_public_key=node2_dh_public_key,
                signature=node2_dh_signature,
                peer_cert=node2_cert)

                node1.calculate_symmetric_key()

                message = b"Hello from Node 1!"
                encrypted_msg, iv, tag, peer_cert = node1.encrypt(message)
                print(type(peer_cert))
                peer_cert_hex=serialize_certificate(peer_cert)
                encrypted_packet = {
                    'encrypted_msg': encrypted_msg.hex(),
                    'iv': iv.hex(),
                    'tag': tag.hex(),
                    'peer_cert':peer_cert_hex
                }
                send_message(conn, json.dumps(encrypted_packet))
                ack=receive_message(conn)
                if ack:
                    ack=json.loads(ack)
                    msg=ack['message']
                    print(type(msg))
                    signature=ack['signature']
                    print(type(signature))
                    node2_ku_hex = ack['ku']  # Extract hexadecimal representation of public key
                    node2_ku = deserialize_ec_public_key(node2_ku_hex)  # Deserialize public key
                    try:
                        print("Verifying acknowledgment signature...")
                        node1.verify_ack_signature(msg.encode('utf-8'), bytes.fromhex(signature), node2_ku)
                        print("Acknowledgment signature verified successfully.")
                    except Exception as e:
                        print("Error verifying acknowledgment signature:", e)

        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            server_socket.close()

if __name__ == "__main__":
    main()