#!/usr/bin/env python3
"""
Crypto Scanner — Flask API
Wraps crypto_scanner.py logic and exposes a JSON REST API.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import ssl
import socket
import struct
import os
import json
import datetime
import warnings
import threading
warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, x25519, x448
    from cryptography.x509.oid import NameOID, ExtensionOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import requests as req_lib
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

app = Flask(__name__)
CORS(app)  # Allow GitHub Pages to call this API

# ── Rate limiting (simple in-memory) ──────────────────────────────────────────
from collections import defaultdict, deque
import time

_rate_store = defaultdict(deque)
_rate_lock  = threading.Lock()

def is_rate_limited(ip, max_requests=10, window=60):
    now = time.time()
    with _rate_lock:
        dq = _rate_store[ip]
        while dq and dq[0] < now - window:
            dq.popleft()
        if len(dq) >= max_requests:
            return True
        dq.append(now)
        return False

# ══════════════════════════════════════════════════════════════════════════════
# PQC DATABASE (same as CLI tool)
# ══════════════════════════════════════════════════════════════════════════════

PQC_DB = {
    "RSA-512":    (0,"CRITICAL","Key Exchange","Shor's","Withdrawn","ML-KEM-768 (FIPS 203)"),
    "RSA-1024":   (0,"CRITICAL","Key Exchange","Shor's","Deprecated","ML-KEM-768 (FIPS 203)"),
    "RSA-2048":   (1,"HIGH","Key Exchange","Shor's","Legacy Only","ML-KEM-768 (FIPS 203)"),
    "RSA-3072":   (1,"HIGH","Key Exchange","Shor's","Legacy Only","ML-KEM-768 (FIPS 203)"),
    "RSA-4096":   (2,"HIGH","Key Exchange","Shor's","Legacy Only","ML-KEM-1024 (FIPS 203)"),
    "RSA":        (1,"HIGH","Key Exchange","Shor's","Legacy Only","ML-KEM-768 (FIPS 203)"),
    "DH-512":     (0,"CRITICAL","Key Exchange","Shor's","Withdrawn","ML-KEM-768 (FIPS 203)"),
    "DH-1024":    (0,"CRITICAL","Key Exchange","Shor's","Deprecated","ML-KEM-768 (FIPS 203)"),
    "DH-2048":    (1,"HIGH","Key Exchange","Shor's","Deprecated","ML-KEM-768 (FIPS 203)"),
    "ECDH-P192":  (0,"CRITICAL","Key Exchange","Shor's","Withdrawn","ML-KEM-768 (FIPS 203)"),
    "ECDH-P224":  (1,"HIGH","Key Exchange","Shor's","Deprecated","ML-KEM-768 (FIPS 203)"),
    "ECDH-P256":  (1,"HIGH","Key Exchange","Shor's","Legacy Only","ML-KEM-768 (FIPS 203)"),
    "ECDH-P384":  (1,"HIGH","Key Exchange","Shor's","Legacy Only","ML-KEM-768 (FIPS 203)"),
    "ECDH-P521":  (1,"HIGH","Key Exchange","Shor's","Legacy Only","ML-KEM-1024 (FIPS 203)"),
    "X25519":     (1,"HIGH","Key Exchange","Shor's","Legacy Only","X25519+ML-KEM-768 hybrid"),
    "X448":       (1,"HIGH","Key Exchange","Shor's","Legacy Only","ML-KEM-1024 (FIPS 203)"),
    "ML-KEM-512": (4,"LOW","Key Exchange","Resistant","FIPS 203 (2024)","Current standard"),
    "ML-KEM-768": (5,"NONE","Key Exchange","Resistant","FIPS 203 (2024)","Current standard"),
    "ML-KEM-1024":(5,"NONE","Key Exchange","Resistant","FIPS 203 (2024)","Current standard"),
    "X25519+ML-KEM-768":   (5,"NONE","Key Exchange","Resistant","IETF Draft","Current standard"),
    "SecP256r1+ML-KEM-768":(5,"NONE","Key Exchange","Resistant","IETF Draft","Current standard"),
    "X25519+ML-KEM-1024":  (5,"NONE","Key Exchange","Resistant","IETF Draft","Current standard"),
    "X25519+Kyber768":     (4,"LOW","Key Exchange","Resistant","Pre-FIPS draft","X25519+ML-KEM-768"),
    "RSA-PSS-2048":  (1,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-65 (FIPS 204)"),
    "RSA-PSS-3072":  (1,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-65 (FIPS 204)"),
    "RSA-PSS-4096":  (2,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-87 (FIPS 204)"),
    "RSA-PKCS1-2048":(1,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-65 (FIPS 204)"),
    "RSA-PKCS1-3072":(1,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-65 (FIPS 204)"),
    "RSA-PKCS1-4096":(2,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-87 (FIPS 204)"),
    "ECDSA-P192": (0,"CRITICAL","Signature","Shor's","Withdrawn","ML-DSA-44 (FIPS 204)"),
    "ECDSA-P224": (1,"HIGH","Signature","Shor's","Deprecated","ML-DSA-44 (FIPS 204)"),
    "ECDSA-P256": (1,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-44 (FIPS 204)"),
    "ECDSA-P384": (1,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-65 (FIPS 204)"),
    "ECDSA-P521": (1,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-87 (FIPS 204)"),
    "Ed25519":    (1,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-44 (FIPS 204)"),
    "Ed448":      (1,"HIGH","Signature","Shor's","Legacy Only","ML-DSA-65 (FIPS 204)"),
    "DSA-1024":   (0,"CRITICAL","Signature","Shor's","Deprecated","ML-DSA-65 (FIPS 204)"),
    "DSA-2048":   (1,"HIGH","Signature","Shor's","Deprecated","ML-DSA-65 (FIPS 204)"),
    "ML-DSA-44":  (5,"NONE","Signature","Resistant","FIPS 204 (2024)","Current standard"),
    "ML-DSA-65":  (5,"NONE","Signature","Resistant","FIPS 204 (2024)","Current standard"),
    "ML-DSA-87":  (5,"NONE","Signature","Resistant","FIPS 204 (2024)","Current standard"),
    "SLH-DSA-128s":(5,"NONE","Signature","Resistant","FIPS 205 (2024)","Current standard"),
    "FN-DSA-512": (5,"NONE","Signature","Resistant","FIPS 206 (2024)","Current standard"),
    "FN-DSA-1024":(5,"NONE","Signature","Resistant","FIPS 206 (2024)","Current standard"),
    "DES":              (0,"CRITICAL","Symmetric","Grover's","Withdrawn","AES-256-GCM"),
    "3DES":             (0,"CRITICAL","Symmetric","Grover's","Deprecated 2023","AES-256-GCM"),
    "RC4":              (0,"CRITICAL","Symmetric","Grover's","Withdrawn","ChaCha20-Poly1305"),
    "AES-128-CBC":      (2,"MEDIUM","Symmetric","Grover's","Legacy","AES-256-GCM"),
    "AES-128-GCM":      (3,"MEDIUM","Symmetric","Grover's","Approved","AES-256-GCM"),
    "AES-128-ECB":      (1,"HIGH","Symmetric","Grover's","Mode Insecure","AES-256-GCM"),
    "AES-256-CBC":      (4,"LOW","Symmetric","Grover's","Approved","AES-256-GCM (prefer GCM)"),
    "AES-256-GCM":      (5,"NONE","Symmetric","Resistant","FIPS 197","Current standard"),
    "AES-256-CTR":      (4,"LOW","Symmetric","Resistant","FIPS 197","AES-256-GCM (add AEAD)"),
    "ChaCha20-Poly1305":(5,"NONE","Symmetric","Resistant","RFC 8439","Current standard"),
    "MD5":     (0,"CRITICAL","Hash","Grover's","Withdrawn","SHA-256 minimum"),
    "SHA-1":   (0,"CRITICAL","Hash","Grover's","Deprecated 2022","SHA-256 minimum"),
    "SHA-224": (3,"MEDIUM","Hash","Grover's","FIPS 180-4","SHA-384"),
    "SHA-256": (4,"LOW","Hash","Grover's","FIPS 180-4","SHA-384 for high assurance"),
    "SHA-384": (5,"NONE","Hash","Resistant","FIPS 180-4","Current standard"),
    "SHA-512": (5,"NONE","Hash","Resistant","FIPS 180-4","Current standard"),
    "SHA3-256":(4,"LOW","Hash","Grover's","FIPS 202","SHA3-384 for high assurance"),
    "SHA3-384":(5,"NONE","Hash","Resistant","FIPS 202","Current standard"),
    "SHA3-512":(5,"NONE","Hash","Resistant","FIPS 202","Current standard"),
    "SSL-2.0": (0,"CRITICAL","Protocol","N/A","Withdrawn","TLS 1.3 + ML-KEM hybrid"),
    "SSL-3.0": (0,"CRITICAL","Protocol","N/A","Withdrawn","TLS 1.3 + ML-KEM hybrid"),
    "TLS-1.0": (0,"CRITICAL","Protocol","N/A","Deprecated 2021","TLS 1.3 + ML-KEM hybrid"),
    "TLS-1.1": (0,"CRITICAL","Protocol","N/A","Deprecated 2021","TLS 1.3 + ML-KEM hybrid"),
    "TLS-1.2": (2,"MEDIUM","Protocol","Depends","Conditional","TLS 1.3 + ML-KEM hybrid"),
    "TLS-1.3": (4,"LOW","Protocol","Classical KEX","Recommended","TLS 1.3 + X25519+ML-KEM-768"),
}

TLS_GROUPS = {
    0x0017:"ECDH-P256", 0x0018:"ECDH-P384", 0x0019:"ECDH-P521",
    0x001D:"X25519",    0x001E:"X448",
    0x11ec:"X25519+ML-KEM-768", 0x11eb:"SecP256r1+ML-KEM-768",
    0x6399:"X25519+ML-KEM-768", 0x639a:"X25519+ML-KEM-1024",
    0x0200:"X25519+Kyber768",
    0x0203:"ML-KEM-768", 0x0204:"ML-KEM-1024",
}

KEX_DESCRIPTIONS = {
    "X25519+ML-KEM-768":    "X25519 + ML-KEM-768 hybrid (IANA 0x{id:04x}) — session traffic is quantum-safe",
    "SecP256r1+ML-KEM-768": "P-256 + ML-KEM-768 hybrid (IANA 0x{id:04x}) — session traffic is quantum-safe",
    "X25519+ML-KEM-1024":   "X25519 + ML-KEM-1024 hybrid (IANA 0x{id:04x}) — quantum-safe",
    "X25519+Kyber768":      "X25519 + Kyber768 pre-standard hybrid (IANA 0x{id:04x})",
    "X25519":               "X25519 elliptic curve (IANA 0x{id:04x}) — classical only, no PQC",
    "ECDH-P256":            "ECDH P-256 (IANA 0x{id:04x}) — classical only, no PQC",
    "ECDH-P384":            "ECDH P-384 (IANA 0x{id:04x}) — classical only, no PQC",
    "ML-KEM-768":           "Pure ML-KEM-768 (IANA 0x{id:04x}) — fully quantum-safe",
    "ML-KEM-1024":          "Pure ML-KEM-1024 (IANA 0x{id:04x}) — fully quantum-safe",
}

# ══════════════════════════════════════════════════════════════════════════════
# SCANNER LOGIC
# ══════════════════════════════════════════════════════════════════════════════

def pqc_lookup(algo):
    entry = PQC_DB.get(algo)
    if not entry:
        return {"rating":3,"threat":"UNKNOWN","category":"Unknown",
                "quantum":"Unknown","nist":"Unknown","migrate":"Unknown"}
    return {"rating":entry[0],"threat":entry[1],"category":entry[2],
            "quantum":entry[3],"nist":entry[4],"migrate":entry[5]}


def build_client_hello(host):
    groups = [0x11ec,0x11eb,0x6399,0x639a,0x0203,0x0204,0x001D,0x001E,0x0017,0x0018,0x0019]
    groups_data = b"".join(struct.pack("!H",g) for g in groups)
    supported_groups_ext = struct.pack("!HH",0x000a,len(groups_data)+2) + struct.pack("!H",len(groups_data)) + groups_data
    sni_name = host.encode()
    sni_ext = (struct.pack("!HH",0x0000,len(sni_name)+5) +
               struct.pack("!H",len(sni_name)+3) + b"\x00" +
               struct.pack("!H",len(sni_name)) + sni_name)
    sv_ext = struct.pack("!HHB",0x002b,3,2) + struct.pack("!H",0x0304)
    sig_algs_data = struct.pack("!HHHHHH",0x0403,0x0503,0x0603,0x0804,0x0805,0x0806)
    sig_ext = struct.pack("!HHH",0x000d,len(sig_algs_data)+2,len(sig_algs_data)) + sig_algs_data
    kx_entry = struct.pack("!HH",0x001D,32) + os.urandom(32)
    ks_ext = struct.pack("!HHH",0x0033,len(kx_entry)+2,len(kx_entry)) + kx_entry
    extensions = sni_ext + supported_groups_ext + sv_ext + sig_ext + ks_ext
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    ciphers = struct.pack("!HHHH",0x1301,0x1302,0x1303,0x00ff)
    body = (struct.pack("!H",0x0303) + random_bytes +
            struct.pack("!B",len(session_id)) + session_id +
            struct.pack("!H",len(ciphers)) + ciphers +
            b"\x01\x00" + struct.pack("!H",len(extensions)) + extensions)
    hs = b"\x01" + struct.pack("!I",len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H",len(hs)) + hs


def probe_kex_group(host, port=443, timeout=6):
    try:
        sock = socket.create_connection((host,port),timeout=timeout)
        sock.sendall(build_client_hello(host))
        data = b""
        sock.settimeout(4)
        try:
            while len(data) < 4096:
                chunk = sock.recv(4096)
                if not chunk: break
                data += chunk
                if len(data) > 200: break
        except socket.timeout:
            pass
        sock.close()
        pos = 0
        while pos < len(data) - 5:
            rec_type = data[pos]
            rec_len  = struct.unpack("!H",data[pos+3:pos+5])[0]
            payload  = data[pos+5:pos+5+rec_len]
            pos     += 5 + rec_len
            if rec_type != 0x16 or not payload or payload[0] != 0x02:
                continue
            p = 4 + 2 + 32
            sid_len = payload[p]; p += 1 + sid_len + 2 + 1
            if p + 2 > len(payload): break
            ext_total = struct.unpack("!H",payload[p:p+2])[0]
            p += 2; end = p + ext_total
            while p + 4 <= end:
                ext_type = struct.unpack("!H",payload[p:p+2])[0]
                ext_len  = struct.unpack("!H",payload[p+2:p+4])[0]
                ext_data = payload[p+4:p+4+ext_len]
                p       += 4 + ext_len
                if ext_type == 0x0033 and len(ext_data) >= 2:
                    group_id = struct.unpack("!H",ext_data[0:2])[0]
                    return group_id, TLS_GROUPS.get(group_id, f"Unknown(0x{group_id:04x})")
    except Exception:
        pass
    return None, None


def parse_cipher_suite(cipher_name):
    algos = []
    name = cipher_name.upper().replace("-","_")
    if   "ECDHE" in name: algos.append(("ECDH-P256","Key exchange (ECDHE)"))
    elif "DHE"   in name: algos.append(("DH-2048",  "Key exchange (DHE)"))
    elif name.startswith("RSA_") or name.startswith("TLS_RSA"):
        algos.append(("RSA-2048","Key exchange (RSA static)"))
    if   "AES_256_GCM"       in name: algos.append(("AES-256-GCM","Symmetric encryption"))
    elif "AES_128_GCM"       in name: algos.append(("AES-128-GCM","Symmetric encryption"))
    elif "AES_256_CBC"       in name: algos.append(("AES-256-CBC","Symmetric encryption"))
    elif "AES_128_CBC"       in name: algos.append(("AES-128-CBC","Symmetric encryption"))
    elif "CHACHA20_POLY1305" in name: algos.append(("ChaCha20-Poly1305","Symmetric encryption"))
    elif "3DES"              in name: algos.append(("3DES","Symmetric encryption"))
    elif "RC4"               in name: algos.append(("RC4","Symmetric encryption"))
    if   "SHA384" in name or "SHA_384" in name: algos.append(("SHA-384","MAC/PRF"))
    elif "SHA256" in name or "SHA_256" in name: algos.append(("SHA-256","MAC/PRF"))
    elif "_SHA"  in name and "SHA2" not in name: algos.append(("SHA-1","MAC/PRF"))
    elif "MD5"   in name: algos.append(("MD5","MAC/PRF"))
    return algos


def _fetch_aia_intermediates(leaf_der, seen_urls=None, depth=0):
    """
    Walk the AIA caIssuers chain: fetch intermediate certs referenced in the
    leaf (and each intermediate) until we reach a self-signed root or depth limit.
    Returns [(role, der_bytes), ...] NOT including the leaf itself.
    """
    if depth > 4 or not HAS_CRYPTO:
        return []
    if seen_urls is None:
        seen_urls = set()
    try:
        from cryptography.x509 import (
            AuthorityInformationAccess, ExtensionNotFound
        )
        from cryptography.x509.oid import AuthorityInformationAccessOID
        cert = x509.load_der_x509_certificate(leaf_der)
        try:
            aia = cert.extensions.get_extension_for_class(AuthorityInformationAccess)
            urls = [
                desc.access_location.value
                for desc in aia.value
                if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            ]
        except ExtensionNotFound:
            return []

        results = []
        for url in urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                import urllib.request
                with urllib.request.urlopen(url, timeout=5) as resp:
                    raw = resp.read()
                # Could be DER or PEM
                if raw.strip().startswith(b"-----"):
                    import base64
                    b64 = b"".join(raw.split(b"\n")[1:-2])
                    der = base64.b64decode(b64)
                else:
                    der = raw
                # Check if self-signed (root)
                iss_cert = x509.load_der_x509_certificate(der)
                is_root = (iss_cert.subject == iss_cert.issuer)
                role = "root" if is_root else "intermediate"
                results.append((role, der))
                if not is_root:
                    results.extend(_fetch_aia_intermediates(der, seen_urls, depth+1))
            except Exception:
                continue
        return results
    except Exception:
        return []


def get_cert_chain(host, port=443, timeout=10):
    """
    Fetch the full cert chain: leaf from TLS handshake, then walk AIA to get
    intermediates and root. Returns [(role, der_bytes), ...] leaf first.
    """
    leaf_der = None
    handshake_chain = []  # what the server voluntarily sent

    # Try pyOpenSSL first — gets whatever the server sent
    try:
        from OpenSSL import SSL, crypto as ossl_crypto
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
        sock = socket.create_connection((host, port), timeout=timeout)
        conn = SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(host.encode())
        conn.set_connect_state()
        conn.do_handshake()
        chain = conn.get_peer_cert_chain()
        conn.close(); sock.close()
        for i, cert in enumerate(chain or []):
            der = ossl_crypto.dump_certificate(ossl_crypto.FILETYPE_ASN1, cert)
            if i == 0:
                leaf_der = der
            handshake_chain.append(der)
    except Exception:
        pass

    # Fallback: stdlib for leaf only
    if not leaf_der:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as conn:
                    leaf_der = conn.getpeercert(binary_form=True)
        except Exception:
            return []

    if not leaf_der:
        return []

    result = [("leaf", leaf_der)]

    # If server sent full chain, use it (minus the leaf we already have)
    if len(handshake_chain) > 1:
        for i, der in enumerate(handshake_chain[1:], 1):
            role = "root" if i == len(handshake_chain) - 1 else "intermediate"
            result.append((role, der))
    else:
        # Server sent leaf only — chase AIA to build the chain ourselves
        aia_chain = _fetch_aia_intermediates(leaf_der)
        result.extend(aia_chain)

    return result


def parse_cert(der_bytes, role="leaf"):
    """
    Parse one certificate. role = leaf | intermediate | root.
    leaf:         full analysis + meta dict
    intermediate: signing key + hash (weakest-link)
    root:         signing key only (self-signed; hash is less meaningful)
    """
    if not HAS_CRYPTO:
        return [], {}
    findings = []
    import re as _re
    ROLE_LABEL = {"leaf":"Leaf certificate","intermediate":"Intermediate CA","root":"Root CA"}
    label = ROLE_LABEL.get(role, "Certificate")
    try:
        cert    = x509.load_der_x509_certificate(der_bytes)
        sig_oid = cert.signature_algorithm_oid.dotted_string
        cn_list = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn      = cn_list[0].value if cn_list else "N/A"
        iss_list= cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer  = iss_list[0].value if iss_list else "N/A"

        if role != "root" and cert.signature_hash_algorithm:
            raw = cert.signature_hash_algorithm.name.upper()
            hash_norm = _re.sub(r'SHA(\d)',r'SHA-\1',raw).replace("SHA-3-","SHA3-")
            findings.append({"ftype":"sig_hash","algo":hash_norm,
                "context":f"{label} ({cn}) — signature hash algorithm",
                "source":f"OID {sig_oid}"})

        pub = cert.public_key()
        curve_map = {"secp256r1":"P256","secp384r1":"P384","secp521r1":"P521",
                     "secp192r1":"P192","secp224r1":"P224"}
        if isinstance(pub, rsa.RSAPublicKey):
            bits = pub.key_size
            algo = f"RSA-PSS-{bits}" if "1.2.840.113549.1.1.10" in sig_oid else f"RSA-PKCS1-{bits}"
            findings.append({"ftype":"sig_key","algo":algo,
                "context":f"{label} ({cn}) — {bits}-bit RSA signing key",
                "source":"SubjectPublicKeyInfo"})
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            curve = pub.curve.name
            findings.append({"ftype":"sig_key","algo":"ECDSA-"+curve_map.get(curve,curve),
                "context":f"{label} ({cn}) — {curve} signing key",
                "source":"SubjectPublicKeyInfo"})
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            findings.append({"ftype":"sig_key","algo":"Ed25519",
                "context":f"{label} ({cn}) — Ed25519 signing key","source":"SubjectPublicKeyInfo"})
        elif isinstance(pub, ed448.Ed448PublicKey):
            findings.append({"ftype":"sig_key","algo":"Ed448",
                "context":f"{label} ({cn}) — Ed448 signing key","source":"SubjectPublicKeyInfo"})

        if role == "leaf":
            try:
                ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                if ski:
                    findings.append({"ftype":"ski_info","algo":"SHA-1",
                        "context":"Subject Key Identifier (RFC 5280 §4.2.1.2 — identifier only, not security-relevant)",
                        "source":"X.509 Extension"})
            except: pass

        meta = {}
        if role == "leaf":
            meta = {
                "subject": cn, "issuer": issuer,
                "not_before": str(cert.not_valid_before_utc if hasattr(cert,"not_valid_before_utc") else cert.not_valid_before),
                "not_after":  str(cert.not_valid_after_utc  if hasattr(cert,"not_valid_after_utc")  else cert.not_valid_after),
            }
        return findings, meta
    except Exception:
        return [], {}


def do_scan(host, port=443):
    findings = []
    meta     = {"host": host, "port": port,
                "scanned_at": datetime.datetime.utcnow().isoformat() + "Z"}

    # IP
    try:
        meta["ip"] = socket.gethostbyname(host)
    except:
        meta["ip"] = "resolution failed"

    # TLS connect
    tls_ver = None
    der_cert = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as conn:
                tls_ver  = conn.version()
                cipher   = conn.cipher()
                der_cert = conn.getpeercert(binary_form=True)
                meta["alpn"] = conn.selected_alpn_protocol()
    except ssl.SSLCertVerificationError:
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False; ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as raw:
                with ctx2.wrap_socket(raw, server_hostname=host) as conn:
                    tls_ver  = conn.version()
                    cipher   = conn.cipher()
                    der_cert = conn.getpeercert(binary_form=True)
                    meta["cert_warning"] = "Certificate verification failed"
        except Exception as e:
            return {"error": str(e)}, meta
    except Exception as e:
        return {"error": str(e)}, meta

    # TLS version finding
    ver_map = {"TLSv1.3":"TLS-1.3","TLSv1.2":"TLS-1.2","TLSv1.1":"TLS-1.1","TLSv1":"TLS-1.0"}
    ver_key = ver_map.get(tls_ver, tls_ver)
    meta["tls_version"] = tls_ver
    findings.append({"algo": ver_key,
                     "context": f"Negotiated protocol version: {tls_ver}",
                     "source": "TLS handshake", **pqc_lookup(ver_key)})

    # Supported versions
    supported = []
    for pn, pc in [("TLS-1.3", getattr(ssl.TLSVersion,"TLSv1_3",None)),
                   ("TLS-1.2", getattr(ssl.TLSVersion,"TLSv1_2",None))]:
        if not pc: continue
        try:
            ctx_v = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_v.check_hostname = False; ctx_v.verify_mode = ssl.CERT_NONE
            ctx_v.minimum_version = pc; ctx_v.maximum_version = pc
            with socket.create_connection((host, port), timeout=4) as raw:
                with ctx_v.wrap_socket(raw, server_hostname=host):
                    supported.append(pn)
        except: pass
    meta["supported_versions"] = supported
    for v in supported:
        if v != ver_key:
            findings.append({"algo": v, "context": "Also accepted by server",
                             "source": "Version enumeration", **pqc_lookup(v)})

    # KEX group probe (TLS 1.3 only)
    if ver_key == "TLS-1.3":
        kex_id, kex_name = probe_kex_group(host, port)
        if kex_name:
            desc = KEX_DESCRIPTIONS.get(kex_name, f"Key exchange group (IANA 0x{kex_id:04x})").format(id=kex_id)
            meta["kex_group"] = kex_name
            findings.append({"algo": kex_name, "context": desc,
                             "source": "Raw TLS ServerHello → key_share extension",
                             **pqc_lookup(kex_name)})
    else:
        meta["kex_probe"] = f"Skipped — server uses {tls_ver}, not TLS 1.3. TLS 1.2 cannot use PQC hybrid key exchange."

    # Cipher suite
    if cipher:
        meta["cipher_suite"] = cipher[0]
        for algo, ctx_str in parse_cipher_suite(cipher[0]):
            findings.append({"algo": algo, "context": ctx_str,
                             "source": f"Cipher suite: {cipher[0]}", **pqc_lookup(algo)})

    # Certificate chain: leaf + intermediates + root
    if HAS_CRYPTO:
        chain = get_cert_chain(host, port)
        if not chain and der_cert:
            chain = [("leaf", der_cert)]
        chain_meta = []
        for role, der in chain:
            cert_findings, cert_meta = parse_cert(der_bytes=der, role=role)
            if role == "leaf" and cert_meta:
                meta["certificate"] = cert_meta
            for f in cert_findings:
                if f["ftype"] == "ski_info":
                    meta["ski_note"] = f["context"]
                    continue
                findings.append({"algo": f["algo"], "context": f["context"],
                                 "source": f["source"], **pqc_lookup(f["algo"])})
            if cert_meta:
                chain_meta.append({"role": role, **cert_meta})
        meta["cert_chain"] = chain_meta

    # HTTP headers
    if HAS_REQUESTS:
        try:
            scheme = "https" if port in (443,8443) else "http"
            r = req_lib.get(f"{scheme}://{host}:{port}/", timeout=8,
                            verify=False, allow_redirects=True,
                            headers={"User-Agent":"CryptoScanner/1.0"})
            hdrs = {k.lower():v for k,v in r.headers.items()}
            meta["http_status"]  = r.status_code
            meta["final_url"]    = r.url
            meta["hsts"]         = hdrs.get("strict-transport-security","")
            meta["server"]       = hdrs.get("server","")
        except: pass

    # Score
    scores = [f["rating"] for f in findings]
    portfolio = round(sum(scores)/len(scores)) if scores else 3

    # HNDL vs impersonation risk
    kex_cats = {"Key Exchange","Protocol"}
    hndl_count = sum(1 for f in findings
                     if f["threat"] in ("CRITICAL","HIGH") and f["category"] in kex_cats)
    sig_count  = sum(1 for f in findings
                     if f["threat"] in ("CRITICAL","HIGH") and f["category"] == "Signature")

    return {
        "findings":        findings,
        "portfolio_score": portfolio,
        "portfolio_label": ["Broken","Critical","Insecure","Marginal","Acceptable","PQC Safe"][portfolio],
        "hndl_risk":       hndl_count > 0,
        "hndl_count":      hndl_count,
        "impersonation_risk": sig_count > 0,
        "impersonation_count": sig_count,
    }, meta


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.datetime.utcnow().isoformat()})


@app.route("/scan")
def scan():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if is_rate_limited(ip):
        return jsonify({"error": "Rate limit exceeded. Max 10 scans per minute."}), 429

    domain = request.args.get("domain","").strip()
    port   = request.args.get("port", 443)

    if not domain:
        return jsonify({"error": "Missing ?domain= parameter"}), 400

    # Sanitise — only allow hostname characters
    import re
    domain = domain.replace("https://","").replace("http://","").rstrip("/").split("/")[0]
    if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
        return jsonify({"error": "Invalid domain"}), 400

    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        return jsonify({"error": "Invalid port"}), 400

    # Block private IPs
    try:
        ip_obj = ipaddress.ip_address(socket.gethostbyname(domain))
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return jsonify({"error": "Private/internal addresses not allowed"}), 403
    except: pass

    import ipaddress
    result, meta = do_scan(domain, port)
    if "error" in result:
        return jsonify({"error": result["error"], "meta": meta}), 502

    return jsonify({"meta": meta, **result})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
