from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

def gen_cert(pub_key, ca_priv_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'BE'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Oost-Vlaanderen'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'Gent'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'UGent'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'Groep 18'),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        pub_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).sign(ca_priv_key, hashes.SHA256(), default_backend())

    return cert

def create_pub_priv_key_pair(name, ca_pr):
    print(name)
    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )

    public_key = private_key.public_key()
    cert = gen_cert(public_key, private_key)  # Pass the private key for signing

    # Write everything to files
    print('certificate: certificates/' + name + '_CERT.pem')
    with open('certificates/' + name + '_CERT.pem', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print('private key: certificates/' + name + '_KR.pem')
    with open('certificates/' + name + '_KR.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def create_certificates():
    # Create public/private key pair for the CA
    print('Creating CA public/private key pair')
    ca_pr = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    ca_pu = ca_pr.public_key()

    # Write the public/private key to a file
    print('public keyfile: certificates/CA_KU.pem')
    with open('certificates/CA_KU.pem', 'wb') as f:
        f.write(ca_pu.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print('public keyfile: certificates/CA_KR.pem')
    with open('certificates/CA_KR.pem', 'wb') as f:
        f.write(ca_pr.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Create public/private key pair and certificate for Node1
    print('Creating public/private key pair and certificate for Node1')
    create_pub_priv_key_pair('Node1', ca_pr)

    # Create public/private key pair and certificate for Node2
    print('Creating public/private key pair and certificate for Node2')
    create_pub_priv_key_pair('Node2', ca_pr)

if __name__ == "__main__":
    create_certificates()
