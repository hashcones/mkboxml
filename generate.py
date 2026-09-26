#!/usr/bin/env python3
import datetime
import xml.etree.ElementTree as ET
from xml.dom import minidom
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def generate_mock_rkp_chain():
    print("[*] Generating ECDSA SECP256R1 Keypair...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Define validation window
    one_day = datetime.timedelta(days=1)
    start_time = datetime.datetime.now(datetime.timezone.utc) - one_day
    end_time = datetime.datetime.now(datetime.timezone.utc) + (one_day * 365)

    # 1. Generate Root CA
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mock Google RKP Root CA")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start_time)
        .not_valid_after(end_time)
        .sign(private_key, hashes.SHA256())
    )

    # 2. Generate Intermediate CA 2
    int2_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mock Google RKP Intermediate 2")])
    int2_cert = (
        x509.CertificateBuilder()
        .subject_name(int2_name)
        .issuer_name(root_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start_time)
        .not_valid_after(end_time)
        .sign(private_key, hashes.SHA256())
    )

    # 3. Generate Intermediate CA 1
    int1_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mock Google RKP Intermediate 1")])
    int1_cert = (
        x509.CertificateBuilder()
        .subject_name(int1_name)
        .issuer_name(int2_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start_time)
        .not_valid_after(end_time)
        .sign(private_key, hashes.SHA256())
    )

    # 4. Generate Leaf Certificate (With custom KeyMint v4 placeholder profiles)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mock RKP KeyMint v4 Leaf")])
    
    # Optional: Custom OID 1.3.6.1.4.1.11129.2.1.17 maps to Android Key Attestation Extension
    # For advanced parsing, hex/ASN.1 data representing KeyMint V4 goes here.
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(int1_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start_time)
        .not_valid_after(end_time)
        .sign(private_key, hashes.SHA256())
    )

    # Serialize private key to PEM string
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Serialize certificates to PEM strings
    certs_pem = [
        cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        for cert in [leaf_cert, int1_cert, int2_cert, root_cert]
    ]

    return priv_pem, certs_pem

def build_keybox_xml(priv_pem, certs_pem, filename="keybox.xml"):
    print(f"[*] Building XML structural layout for {filename}...")
    
    # Root element element block
    root = ET.Element("AndroidAttestation")
    num_boxes = ET.SubElement(root, "NumberOfKeyboxes")
    num_boxes.text = "1"
    
    # Individual device container block
    keybox = ET.SubElement(root, "Keybox", DeviceID="MOCK_RKP_KEYMINT_V4")
    key_node = ET.SubElement(keybox, "Key", algorithm="ecdsa")
    
    # Inject OpenSSL formatted Private Key
    priv_node = ET.SubElement(key_node, "Private")
    priv_node.text = f"\n{priv_pem.strip()}\n"
    
    # Setup chain structural layout 
    chain_node = ET.SubElement(key_node, "CertificateChain")
    for idx, cert_pem in enumerate(certs_pem, 1):
        cert_node = ET.SubElement(chain_node, "Certificate")
        cert_node.text = f"\n{cert_pem.strip()}\n"
        
    # Format and pretty-print XML tree
    xml_str = ET.tostring(root, encoding='utf-8')
    parsed_xml = minidom.parseString(xml_str)
    pretty_xml = parsed_xml.toprettyxml(indent="  ")
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(pretty_xml)
    print(f"[+] Output generated successfully matching specifications: {filename}")

if __name__ == "__main__":
    priv_key, cert_chain = generate_mock_rkp_chain()
    build_keybox_xml(priv_key, cert_chain)
