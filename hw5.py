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

# Packet body encoding:  "type|seq|hexdata"
# Final wire format: [4-byte length][packet bytes]


def build_packet(ptype: str, seq, payload: bytes = b"") -> bytes:
    """
    Creates a safe packet body with hex payload.
    """
    # payload → hex string
    if isinstance(payload, bytes):
        payload_hex = payload.hex()
    else:
        payload_hex = payload

    body = f"{ptype}|{seq}|{payload_hex}".encode("utf-8")

    # prefix with 4-byte length
    header = struct.pack("!I", len(body))
    return header + body


def try_parse_packet(buffer: bytearray):
    """
    Try to extract one complete length-prefixed packet from buffer.
    Returns (packet_dict, consumed_bytes) or (None, 0).
    """

    # Need at least 4 bytes for length
    if len(buffer) < 4:
        return None, 0

    pkt_len = struct.unpack("!I", buffer[:4])[0]

    # Need the full packet
    if len(buffer) < 4 + pkt_len:
        return None, 0

    raw = buffer[4:4 + pkt_len]

    text = raw.decode("utf-8", errors="ignore")
    parts = text.split("|", 2)
    if len(parts) != 3:
        return None, 4 + pkt_len

    ptype, seq_str, payload_hex = parts

    # parse seq
    if seq_str.isdigit():
        seq = int(seq_str)
    else:
        seq = seq_str  # "fin"

    # parse hex payload
    try:
        if payload_hex:
            payload = bytes.fromhex(payload_hex)
        else:
            payload = b""
    except ValueError:
        return None, 4 + pkt_len

    pkt = {
        "type": ptype,
        "seq": seq,
        "payload": payload
    }

    return pkt, 4 + pkt_len



# ================================================================
# =========================== SENDER =============================
# ================================================================

def send(sock: socket.socket, data: bytes):
    logger = homework5.logging.get_logger("hw5-sender")

    seq = 0
    max_payload = homework5.MAX_PACKET - 200  # leave headroom

    # RTT estimator
    est_rtt = 0.5
    dev_rtt = 0.25
    timeout = est_rtt + 4 * dev_rtt

    pos = 0
    total = len(data)

    recv_buf = bytearray()

    # ========================= SEND DATA ==========================
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

                # Try to parse ACK
                pkt_obj, consumed = try_parse_packet(recv_buf)
                if consumed > 0:
                    del recv_buf[:consumed]

                if pkt_obj and pkt_obj["type"] == "ack" and pkt_obj["seq"] == seq:
                    # RTT update
                    sample = time.time() - send_time
                    est_rtt = 0.875 * est_rtt + 0.125 * sample
                    dev_rtt = 0.75 * dev_rtt + 0.25 * abs(sample - est_rtt)
                    timeout = est_rtt + 4 * dev_rtt
                    break

            except socket.timeout:
                logger.info(f"Timeout waiting for ack seq={seq}, resending...")
                continue

        pos += max_payload
        seq += 1

    # ========================= FIN HANDSHAKE ======================
    finpkt = build_packet("fin", "fin", b"")
    recv_buf = bytearray()

    while True:
        sock.send(finpkt)
        sock.settimeout(timeout)
        try:
            chunk = sock.recv(4096)
            recv_buf.extend(chunk)

            pkt_obj, consumed = try_parse_packet(recv_buf)
            if consumed > 0:
                del recv_buf[:consumed]

            if pkt_obj and pkt_obj["type"] == "ack" and pkt_obj["seq"] == "fin":
                break
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
                    break  # need more data

                del recv_buf[:consumed]

                if not pkt_obj:
                    continue

                ptype = pkt_obj["type"]

                if ptype == "data":
                    seq = pkt_obj["seq"]
                    payload = pkt_obj["payload"]

                    if seq == expected:
                        dest.write(payload)
                        dest.flush()
                        num_bytes += len(payload)

                        ack = build_packet("ack", expected, b"")
                        sock.send(ack)
                        expected += 1
                    else:
                        # duplicate/out of order — re-ACK last correct
                        ack = build_packet("ack", expected - 1, b"")
                        sock.send(ack)

                elif ptype == "fin":
                    ack = build_packet("ack", "fin", b"")
                    sock.send(ack)
                    return num_bytes

        except socket.timeout:
            continue
