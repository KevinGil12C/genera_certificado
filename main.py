from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat, PrivateFormat
from cryptography.x509 import CertificateBuilder
from cryptography.x509 import NameOID
import datetime
import cryptography.x509 as x509

def generate_certificate():
    # Solicitar información al usuario
    nombre = input("Ingrese su nombre: ")
    apodo = input("Ingrese su apodo: ")
    nombre_favorito = input("Ingrese su nombre favorito: ")
    password = input("Ingrese una contraseña para la clave privada: ").encode()

    # Generar clave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Generar la clave pública
    public_key = private_key.public_key()

    # Crear un certificado auto-firmado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, nombre),
        x509.NameAttribute(NameOID.GIVEN_NAME, apodo),
        x509.NameAttribute(NameOID.SURNAME, nombre_favorito)
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    
    cert_builder = x509.CertificateBuilder(
        issuer_name=issuer,
        subject_name=subject,
        public_key=public_key,
        serial_number=x509.random_serial_number(),
        not_valid_before=now,
        not_valid_after=now + datetime.timedelta(days=365)
    )

    # Firmar el certificado con la clave privada
    certificate = cert_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256()
    )

    # Serializar el certificado a formato PEM
    cert_pem = certificate.public_bytes(Encoding.PEM)
    priv_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=BestAvailableEncryption(password)
    )

    # Guardar el certificado y la clave privada en archivos
    with open("certificado.pem", "wb") as cert_file:
        cert_file.write(cert_pem)

    with open("clave_privada.pem", "wb") as key_file:
        key_file.write(priv_key_pem)

    print("Certificado y clave privada generados y guardados en archivos.")

if __name__ == "__main__":
    generate_certificate()
