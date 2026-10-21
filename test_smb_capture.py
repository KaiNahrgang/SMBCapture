#!/usr/bin/env python3
"""Local test client for smb_capture.py.

Simulates a Windows NTLMv2 SMB2 authentication handshake against our
capture server and verifies the captured hash is correct.

Usage:
    Terminal 1:  sudo python3 smb_capture.py --port 4455 --out hash.txt
    Terminal 2:  python3 test_smb_capture.py --port 4455

Uses a known password to compute a real NTLMv2 response, so you can
verify the captured hash cracks correctly:
    hashcat -m 5600 hash.txt -a 3 'TestPass123!'
"""

import hashlib
import hmac
import os
import socket
import struct
import sys
import argparse

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
SMB2_MAGIC = b"\xfeSMB"

TEST_USER = "j.park"
TEST_DOMAIN = "ELEVENPP"
TEST_PASSWORD = "TestPass123!"


def netbios_wrap(data):
    return b"\x00" + struct.pack(">I", len(data))[1:] + data


def recv_message(sock):
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    length = struct.unpack(">I", b"\x00" + hdr[1:4])[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def build_smb2_header(command, message_id):
    header = bytearray(64)
    header[0:4] = SMB2_MAGIC
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<H", header, 12, command)
    struct.pack_into("<H", header, 14, 1)           # Credits
    struct.pack_into("<Q", header, 24, message_id)
    return bytes(header)


def build_negotiate_request():
    header = build_smb2_header(0x0000, 0)
    body = bytearray(36)
    struct.pack_into("<H", body, 0, 36)     # StructureSize
    struct.pack_into("<H", body, 2, 1)      # DialectCount
    struct.pack_into("<H", body, 4, 1)      # SecurityMode: signing enabled
    struct.pack_into("<H", body, 34, 0x0202)  # Dialect: SMB 2.0.2
    # Pad to include the dialect
    body += struct.pack("<H", 0x0202)
    return netbios_wrap(header + bytes(body))


def build_ntlmssp_negotiate():
    msg = bytearray()
    msg += NTLMSSP_SIGNATURE
    msg += struct.pack("<I", 1)  # NTLMSSP_NEGOTIATE
    flags = 0x00008000 | 0x00800000 | 0x20000000 | 0x00000001  # NTLM|ALWAYS_SIGN|128|UNICODE
    msg += struct.pack("<I", flags)
    msg += struct.pack("<HHI", 0, 0, 0)  # DomainNameFields (empty)
    msg += struct.pack("<HHI", 0, 0, 0)  # WorkstationFields (empty)
    return bytes(msg)


def build_session_setup(message_id, ntlmssp_blob):
    header = build_smb2_header(0x0001, message_id)
    sec_offset = 64 + 25  # header + fixed body
    body = bytearray(25)
    struct.pack_into("<H", body, 0, 25)            # StructureSize
    struct.pack_into("<B", body, 2, 0)              # Flags
    struct.pack_into("<B", body, 3, 1)              # SecurityMode
    struct.pack_into("<I", body, 4, 0)              # Capabilities
    struct.pack_into("<I", body, 8, 0)              # Channel
    struct.pack_into("<H", body, 12, sec_offset)    # SecurityBufferOffset
    struct.pack_into("<H", body, 14, len(ntlmssp_blob))

    # GSS-API / SPNEGO wrapper not needed — server parses raw NTLMSSP
    body += ntlmssp_blob
    return netbios_wrap(header + bytes(body))


def ntlmv2_response(password, username, domain, server_challenge, client_challenge=None):
    """Compute a real NTLMv2 response.

    Returns (nt_proof_str, client_blob) — the same components the capture
    server extracts and formats for Hashcat.
    """
    if client_challenge is None:
        client_challenge = os.urandom(8)

    # Step 1: NT hash (MD4 of UTF-16LE password)
    nt_hash = hashlib.new("md4", password.encode("utf-16-le")).digest()

    # Step 2: NTLMv2 hash = HMAC-MD5(nt_hash, UPPER(user) + domain in UTF-16LE)
    identity = (username.upper() + domain).encode("utf-16-le")
    ntlmv2_hash = hmac.new(nt_hash, identity, hashlib.md5).digest()

    # Step 3: Build client blob (type 2 / temp)
    import time
    # Windows FILETIME: 100ns intervals since 1601-01-01
    filetime = int((time.time() + 11644473600) * 10_000_000)

    blob = bytearray()
    blob += struct.pack("<I", 0x00000101)   # RespType + HiRespType
    blob += struct.pack("<H", 0)            # Reserved1
    blob += struct.pack("<I", 0)            # Reserved2
    blob += struct.pack("<Q", filetime)     # TimeStamp
    blob += client_challenge                # ChallengeFromClient
    blob += struct.pack("<I", 0)            # Reserved3
    # AV_PAIRS: MsvAvNbDomainName + MsvAvEOL
    av_domain = domain.encode("utf-16-le")
    blob += struct.pack("<HH", 2, len(av_domain)) + av_domain
    blob += struct.pack("<HH", 0, 0)       # MsvAvEOL
    blob = bytes(blob)

    # Step 4: NTProofStr = HMAC-MD5(ntlmv2_hash, server_challenge + blob)
    nt_proof_str = hmac.new(ntlmv2_hash, server_challenge + blob, hashlib.md5).digest()

    return nt_proof_str, blob


def build_ntlmssp_auth(username, domain, nt_proof_str, client_blob):
    """Build NTLMSSP_AUTH message."""
    nt_response = nt_proof_str + client_blob

    # Calculate payload offsets (fixed header is 88 bytes for auth)
    payload_offset = 88
    parts = []

    def add_field(data):
        nonlocal payload_offset
        offset = payload_offset
        parts.append(data)
        payload_offset += len(data)
        return struct.pack("<HHI", len(data), len(data), offset)

    lm_data = b"\x00" * 24  # Empty LM response

    msg = bytearray()
    msg += NTLMSSP_SIGNATURE
    msg += struct.pack("<I", 3)  # NTLMSSP_AUTH

    msg += add_field(lm_data)                                # LmChallengeResponse
    msg += add_field(nt_response)                            # NtChallengeResponse
    msg += add_field(domain.encode("utf-16-le"))             # DomainName
    msg += add_field(username.encode("utf-16-le"))           # UserName
    msg += add_field(b"W\x00O\x00R\x00K\x00S\x00T\x00")    # Workstation "WORKST"
    msg += add_field(b"")                                    # EncryptedRandomSessionKey
    msg += struct.pack("<I", 0x00008000 | 0x00000001)        # NegotiateFlags

    for part in parts:
        msg += part

    return bytes(msg)


def extract_server_challenge(data):
    """Find NTLMSSP_CHALLENGE in an SMB2 response and return the 8-byte challenge."""
    idx = data.find(NTLMSSP_SIGNATURE)
    if idx < 0:
        return None
    blob = data[idx:]
    msg_type = struct.unpack_from("<I", blob, 8)[0]
    if msg_type != 2:
        return None
    return blob[24:32]


def main():
    p = argparse.ArgumentParser(description="Test client for smb_capture.py")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=4455)
    p.add_argument("--user", default=TEST_USER)
    p.add_argument("--domain", default=TEST_DOMAIN)
    p.add_argument("--password", default=TEST_PASSWORD)
    args = p.parse_args()

    print(f"[*] Connecting to {args.host}:{args.port}", flush=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((args.host, args.port))
    except ConnectionRefusedError:
        sys.exit(f"[-] Connection refused — is smb_capture.py running on port {args.port}?")

    # Step 1: SMB2 NEGOTIATE
    print("[*] -> SMB2 NEGOTIATE", flush=True)
    sock.sendall(build_negotiate_request())
    resp = recv_message(sock)
    if resp is None:
        sys.exit("[-] No negotiate response")
    print("[*] <- NEGOTIATE response", flush=True)

    # Step 2: SESSION_SETUP with NTLMSSP_NEGOTIATE
    print("[*] -> SESSION_SETUP (NTLMSSP_NEGOTIATE)", flush=True)
    negotiate_blob = build_ntlmssp_negotiate()
    sock.sendall(build_session_setup(1, negotiate_blob))
    resp = recv_message(sock)
    if resp is None:
        sys.exit("[-] No challenge response")

    server_challenge = extract_server_challenge(resp)
    if server_challenge is None:
        sys.exit("[-] Could not extract server challenge")
    print(f"[*] <- NTLMSSP_CHALLENGE (challenge: {server_challenge.hex()})", flush=True)

    # Step 3: Compute real NTLMv2 response and send AUTH
    nt_proof_str, client_blob = ntlmv2_response(
        args.password, args.user, args.domain, server_challenge)
    auth_blob = build_ntlmssp_auth(args.user, args.domain, nt_proof_str, client_blob)

    print(f"[*] -> SESSION_SETUP (NTLMSSP_AUTH) as {args.domain}\\{args.user}", flush=True)
    sock.sendall(build_session_setup(2, auth_blob))
    resp = recv_message(sock)
    print("[*] <- SESSION_SETUP response", flush=True)

    sock.close()

    print(f"\n[+] Done. The server should have captured the NTLMv2 hash.")
    print(f"[+] Verify with: hashcat -m 5600 hash.txt -a 3 '{args.password}'")


if __name__ == "__main__":
    main()
