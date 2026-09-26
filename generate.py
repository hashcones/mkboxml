#!/usr/bin/env python3
import datetime
import xml.etree.ElementTree as ET
from xml.dom import minidom
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.type import univ, namedtype, tag

# --- ASN.1 Schema Definitions for Android KeyAttestation ---
class AuthorizationList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        # Tag 105: OS Patch Level (Integer format YYYYMM)
        namedtype.OptionalNamedType('osPatchLevel', univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 105)
        )),
        # Tag 718: Vendor Patch Level
        namedtype.OptionalNamedType('vendorPatchLevel', univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 718)
        ))
    )

class KeyDescription(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attestationVersion', univ.Integer()),
        namedtype.NamedType('attestationSecurityLevel', univ.Enumerated()),
        namedtype.NamedType('keymasterVersion', univ.Integer()),
        namedtype.NamedType('keymasterSecurityLevel', univ.Enumerated()),
        namedtype.NamedType('attestationChallenge', univ.OctetString()),
        namedtype.NamedType('uniqueId', univ.OctetString()),
        namedtype.NamedType('softwareEnforced', AuthorizationList()),
        namedtype.NamedType('teeEnforced', AuthorizationList())
    )

def encode_attestation_extension():
    """Converts the patch date into an aligned integer structure that maps correctly"""
    # Define your precise target patch date (Format: YYYYMM)
    target_year = 2026
    target_month = 7
    
    # Calculate bitwise shifts matching Android Keystore specifications
    # (Year << 6) | Month
    encoded_patch_value = (target_year << 6) | target_month
    
    print(f"[*] Compiling bit-shifted Patch Value: {encoded_patch_value} (Maps to {target_year}-{target_month:02d})")

    auth_list = AuthorizationList()
    auth_list.setComponentByName('osPatchLevel', encoded_patch_value)
    auth_list.setComponentByName('vendorPatchLevel', encoded_patch_value)

    key_desc = KeyDescription()
    key_desc.setComponentByName('attestationVersion', 4)
    key_desc.setComponentByName('attestationSecurityLevel', 1) 
    key_desc.setComponentByName('keymasterVersion', 400) 
    key_desc.setComponentByName('keymasterSecurityLevel', 1)
    key_desc.setComponentByName('attestationChallenge', b'MOCK_CHALLENGE')
    key_desc.setComponentByName('uniqueId', b'')
    key_desc.setComponentByName('softwareEnforced', AuthorizationList())
    key_desc.setComponentByName('teeEnforced', auth_list)

    from pyasn1.codec.der import encoder
    return encoder.encode(key_desc)

def generate_mock_rkp_chain():
    print("[*] Generating ECDSA SECP256R1 Keypair...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    one_day = datetime.timedelta(days=1)
    start_time = datetime.datetime.now(datetime.timezone.utc) - one_day
    end_time = datetime.datetime.now(datetime.timezone.utc) + (one_day * 365)

    # 1. Root CA
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Google RKP Root CA")])
    root_cert = x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name).public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(start_time).not_valid_after(end_time).sign(private_key, hashes.SHA256())

    # 2. Intermediate 2
    int2_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Google RKP Intermediate 2")])
    int2_cert = x509.CertificateBuilder().subject_name(int2_name).issuer_name(root_name).public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(start_time).not_valid_after(end_time).sign(private_key, hashes.SHA256())

    # 3. Intermediate 1
    int1_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Google RKP Intermediate 1")])
    int1_cert = x509.CertificateBuilder().subject_name(int1_name).issuer_name(int2_name).public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(start_time).not_valid_after(end_time).sign(private_key, hashes.SHA256())

    # 4. Leaf Certificate (Injecting critical Android Attestation Extension)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RKP KeyMint v4 Leaf")])
    attestation_bytes = encode_attestation_extension()
    
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(int1_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start_time)
        .not_valid_after(end_time)
        # Android Key Description OID
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), attestation_bytes),
            critical=False
        )
        .sign(private_key, hashes.SHA256())
    )

    priv_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
    certs_pem = [cert.public_bytes(serialization.Encoding.PEM).decode('utf-8') for cert in [leaf_cert, int1_cert, int2_cert, root_cert]]

    return priv_pem, certs_pem

def build_keybox_xml(priv_pem, certs_pem, filename="keybox.xml"):
    root = ET.Element("AndroidAttestation")
    ET.SubElement(root, "NumberOfKeyboxes").text = "1"
    keybox = ET.SubElement(root, "Keybox", DeviceID="Xiaomi")
    key_node = ET.SubElement(keybox, "Key", algorithm="ecdsa")
    
    ET.SubElement(key_node, "Private").text = f"\n{priv_pem.strip()}\n"
    chain_node = ET.SubElement(key_node, "CertificateChain")
    for cert_pem in certs_pem:
        ET.SubElement(chain_node, "Certificate").text = f"\n{cert_pem.strip()}\n"
        
    xml_str = ET.tostring(root, encoding='utf-8')
    pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(pretty_xml)
    print(f"[+] Output generated with matching properties: {filename}")

if __name__ == "__main__":
    priv_key, cert_chain = generate_mock_rkp_chain()
    build_keybox_xml(priv_key, cert_chain)
