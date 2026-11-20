#!/usr/bin/env python3
"""Writes a small synthetic capture for demos and the end-to-end test: ordinary DNS and TLS traffic plus one client that
beacons to the same server every 60 s and asks for a generated-looking domain. Everything is invented; addresses are in
documentation ranges (RFC 5737)."""
import struct
import sys

CLIENT, RESOLVER, SERVER, OTHER = "192.168.1.10", "8.8.8.8", "203.0.113.9", "198.51.100.20"


def ip(s):
    return bytes(int(x) for x in s.split("."))


def eth_ipv4(proto, src, dst, l4):
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, ip(src), ip(dst))
    return bytes(12) + b"\x08\x00" + ipv4 + l4


def udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def tcp(sp, dp, payload):
    return struct.pack("!HHIIBBHHH", sp, dp, 1, 0, 0x50, 0x18, 65535, 0, 0) + payload


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_query(name, ident=0x1234):
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(name, addr, ident=0x1234):
    q = dns_name(name) + struct.pack("!HH", 1, 1)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip(addr)
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + q + ans


def dns_nxdomain(name, ident=0x1234):
    return struct.pack("!HHHHHH", ident, 0x8183, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def client_hello(sni):
    name = sni.encode()
    ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + bytes([0x42]) * 32 + b"\0" + struct.pack("!HHH", 4, 0x1301, 0xc02f) + b"\x01\0" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


packets = []  # (timestamp, frame)
t0 = 1_700_000_000

# normal browsing: resolve, then connect once
for i, (name, addr) in enumerate([("www.example.test", OTHER), ("news.example.test", OTHER)]):
    t = t0 + i * 20
    packets.append((t, eth_ipv4(17, CLIENT, RESOLVER, udp(40000 + i, 53, dns_query(name, 100 + i)))))
    packets.append((t, eth_ipv4(17, RESOLVER, CLIENT, udp(53, 40000 + i, dns_response(name, addr, 100 + i)))))
    packets.append((t + 1, eth_ipv4(6, CLIENT, addr, tcp(51000 + i, 443, client_hello(name)))))

# the suspicious client: resolves once, then connects every 60 s (+-1 s) for ten minutes
c2 = "update.cdn-example.test"
packets.append((t0 + 100, eth_ipv4(17, CLIENT, RESOLVER, udp(41000, 53, dns_query(c2, 200)))))
packets.append((t0 + 100, eth_ipv4(17, RESOLVER, CLIENT, udp(53, 41000, dns_response(c2, SERVER, 200)))))
for i in range(10):
    packets.append((t0 + 120 + i * 60 + (i % 3), eth_ipv4(6, CLIENT, SERVER, tcp(52000 + i, 443, client_hello(c2)))))

# a generated-looking name that does not exist
gen = "x7k2q9vz1m4p8d3w.test"
packets.append((t0 + 700, eth_ipv4(17, CLIENT, RESOLVER, udp(42000, 53, dns_query(gen, 300)))))
packets.append((t0 + 700, eth_ipv4(17, RESOLVER, CLIENT, udp(53, 42000, dns_nxdomain(gen, 300)))))

packets.sort(key=lambda p: p[0])
out = sys.argv[1] if len(sys.argv) > 1 else "demo.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, frame in packets:
        f.write(struct.pack("<IIII", ts, 0, len(frame), len(frame)) + frame)
print(f"wrote {out}: {len(packets)} packets")
