import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.packet import Packet, parse_packets
from src.decryption import SimpleModulus

def test_packet_parsing():
    # C1 packet: Type=0xC1, Size=0x04, OpCode=0x00, Data=0x01
    raw = b"\xC1\x04\x00\x01"
    packets = list(parse_packets(raw))
    assert len(packets) == 1
    assert packets[0].type == 0xC1
    assert packets[0].size == 4
    assert packets[0].get_opcode() == 0x00
    print("[SUCCESS] Packet parsing verified.")

def test_simple_modulus_init():
    sm = SimpleModulus()
    assert sm.dec_inverses is not None
    assert len(sm.dec_inverses) == 4
    print("[SUCCESS] SimpleModulus initialization verified.")

if __name__ == "__main__":
    test_packet_parsing()
    test_simple_modulus_init()
