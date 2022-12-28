from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


if __name__ == '__main__':

    private_key_challenger = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key_challenger = private_key_challenger.public_key()

    private_key_prover = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key_prover = private_key_prover.public_key()

    pem = private_key_challenger.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key_challenger.pem', 'wb') as f:
        f.write(pem)

    pem = private_key_prover.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key_prover.pem', 'wb') as f:
        f.write(pem)

    pem = public_key_challenger.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key_challenger.pem', 'wb') as f:
        f.write(pem)

    pem = public_key_prover.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key_prover.pem', 'wb') as f:
        f.write(pem)