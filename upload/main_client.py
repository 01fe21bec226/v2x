import socket
import json
import os
from person import Person
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from certificates import create_certificates, create_pub_priv_key_pair
def deserialize_certificate(hex_data):
    # Convert hexadecimal string back to binary data
    pem_data = bytes.fromhex(hex_data)
    # Deserialize the binary data into a _Certificate object
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return cert
def serialize_ec_public_key(public_key):
    # Serialize the public key to PEM format
    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Convert the PEM data to a hexadecimal string
    hex_data = pem_data.hex()
    return hex_data
def send_message(conn, message):
    conn.sendall(json.dumps(message).encode('utf-8'))

def receive_message(conn):
    data = conn.recv(4096).decode('utf-8')
    print("Received data:", data)  # Add this line to print received data
    return json.loads(data)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect(('localhost', 8085))
        node2 = Person("Node 2")
        node2_dh_public_key, node2_dh_signature = node2.generate_dh_public_key()
        # Receive Node 1's public key and signature from the server
        response = receive_message(conn)
        
        print("Received data:", response)
        if response:
            message = {
                'dh_public_key': node2_dh_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                'dh_signature': node2_dh_signature.hex()
            }
            send_message(conn, json.dumps(message))
            response = json.loads(response)
            node1_dh_public_key = serialization.load_pem_public_key(
                    response['dh_public_key'].encode(),
                    backend=default_backend()
                )
            node1_dh_signature = bytes.fromhex(response['dh_signature'])

            # Verify Node 1's DH public key signature
            print("Verifying signature of public key...")
            # Load Node 1's certificate from file or any other source
            with open('certificates/Node 1_CERT.pem', 'rb') as cert_file:
                node1_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

            # Set Node 1's DH public key as peer public key
            node2.set_dh_peer_public_key(
                dh_peer_public_key=node1_dh_public_key,
                signature=node1_dh_signature,
                peer_cert=node1_cert
            )
            print("done")
            #node1_dh_signature = bytes.fromhex(response['dh_signature']) 
            print("symmetric key calculating\n")
            # Calculate symmetric key
            node2.calculate_symmetric_key()
            print("got symmetric key\n")
            # Send acknowledgment to Node 1
            encrypted_packet=receive_message(conn)
            if response:
               #response = json.loads(response)
               encrypted_packet = json.loads(encrypted_packet)
               encrypted_msg = bytes.fromhex(encrypted_packet['encrypted_msg'])
               iv = bytes.fromhex(encrypted_packet['iv'])
               tag = bytes.fromhex(encrypted_packet['tag'])
               peer_cert = deserialize_certificate(encrypted_packet['peer_cert'])
            decrypted_msg = node2.decrypt(encrypted_msg, iv, tag, peer_cert)
            print("Decrypted message:", decrypted_msg.decode("utf-8"))
            message = b"Acknowledgment from Node 2!"
            signature, node2_ku = node2.sign_ack(message)
           # print(type(node2_ku_s=serialize_ec_public_key(node2_ku)))
            ack_data = {
                'message': message.decode(),
                'signature': signature.hex(),
                'ku': serialize_ec_public_key(node2_ku)
            }
            send_message(conn, json.dumps(ack_data))
if __name__ == "__main__":
    main()