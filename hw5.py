"""
Where solution code to HW5 should be written.  No other files should
be modified.
"""

import socket
import io
import time
import typing
import struct
import homework5
import homework5.logging


# ================================================================
# ========================= UTILITIES ============================
# ================================================================

def build_packet(ptype: str, seq, payload: bytes = b"") -> bytes:
    if isinstance(payload, bytes):
        payload_hex = payload.hex()
    else:
        payload_hex = payload

    body = f"{ptype}|{seq}|{payload_hex}".encode("utf-8")
    header = struct.pack("!I", len(body))
    return header + body


def try_parse_packet(buffer: bytearray):
    if len(buffer) < 4:
        return None, 0

    pkt_len = struct.unpack("!I", buffer[:4])[0]

    if len(buffer) < 4 + pkt_len:
        return None, 0

    raw = buffer[4:4 + pkt_len]
    text = raw.decode("utf-8", errors="ignore")
    parts = text.split("|", 2)
    consumed = 4 + pkt_len

    if len(parts) != 3:
        return None, consumed

    ptype, seq_str, payload_hex = parts

    if seq_str.isdigit():
        seq = int(seq_str)
    else:
        seq = seq_str

    try:
        payload = bytes.fromhex(payload_hex) if payload_hex else b""
    except ValueError:
        return None, consumed

    return {"type": ptype, "seq": seq, "payload": payload}, consumed


# ================================================================
# =========================== SENDER =============================
# ================================================================

def send(sock: socket.socket, data: bytes):
    logger = homework5.logging.get_logger("hw5-sender")

    seq = 0
    max_payload = homework5.MAX_PACKET - 20   # BIGGER CHUNK = FASTER

    est_rtt = 0.2
    dev_rtt = 0.1
    timeout = 0.2

    pos = 0
    total = len(data)

    recv_buf = bytearray()

    while pos < total:
        payload = data[pos:pos + max_payload]
        pkt = build_packet("data", seq, payload)

        while True:
            send_time = time.time()
            sock.send(pkt)
            sock.settimeout(timeout)

            try:
                chunk = sock.recv(4096)
                recv_buf.extend(chunk)

                while True:
                    pkt_obj, consumed = try_parse_packet(recv_buf)
                    if consumed == 0:
                        break
                    del recv_buf[:consumed]

                    if pkt_obj and pkt_obj["type"] == "ack":
                        if pkt_obj["seq"] == seq:
                            sample = time.time() - send_time
                            est_rtt = 0.875 * est_rtt + 0.125 * sample
                            dev_rtt = 0.75 * dev_rtt + 0.25 * abs(sample - est_rtt)
                            timeout = max(0.15, est_rtt + 2 * dev_rtt)
                            break

                else:
                    continue
                break

            except socket.timeout:
                continue

        pos += max_payload
        seq += 1

    # FIN handshake
    finpkt = build_packet("fin", "fin", b"")
    recv_buf = bytearray()

    while True:
        sock.send(finpkt)
        sock.settimeout(timeout)

        try:
            chunk = sock.recv(4096)
            recv_buf.extend(chunk)

            while True:
                pkt_obj, consumed = try_parse_packet(recv_buf)
                if consumed == 0:
                    break
                del recv_buf[:consumed]

                if pkt_obj and pkt_obj["type"] == "ack" and pkt_obj["seq"] == "fin":
                    return

        except socket.timeout:
            continue



# ================================================================
# =========================== RECEIVER ===========================
# ================================================================

def recv(sock: socket.socket, dest: io.BufferedIOBase) -> int:
    logger = homework5.logging.get_logger("hw5-receiver")

    expected = 0
    num_bytes = 0
    recv_buf = bytearray()

    sock.settimeout(1.0)

    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                continue

            recv_buf.extend(chunk)

            while True:
                pkt_obj, consumed = try_parse_packet(recv_buf)

                if consumed == 0:
                    break

                del recv_buf[:consumed]

                if not pkt_obj:
                    continue

                if pkt_obj["type"] == "data":
                    seq = pkt_obj["seq"]
                    payload = pkt_obj["payload"]

                    if seq == expected:
                        dest.write(payload)
                        dest.flush()
                        num_bytes += len(payload)
                        sock.send(build_packet("ack", expected))
                        expected += 1
                    else:
                        sock.send(build_packet("ack", expected - 1))

                elif pkt_obj["type"] == "fin":
                    sock.send(build_packet("ack", "fin"))
                    return num_bytes

        except socket.timeout:
            continue
