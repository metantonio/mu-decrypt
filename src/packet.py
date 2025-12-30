import struct
from .decryption import SimpleModulus

# Common Mu Online OpCodes
OPCODES = {
    0x00: "Chat Message",
    0x01: "Whisper",
    0x02: "Group Chat",
    0x1C: "Move (Walk/Teleport)",
    0x11: "Item Pick Up",
    0x18: "Item Drop",
    0x30: "Cast Skill",
    0xDF: "Character List",
    0xF1: "Connect Level Info",
    0xF3: "Character Select/Create",
    0xF4: "ConnectServer Info/List",
}

class Packet:
    """
    Base class for Mu Online packets.
    Handles the common headers: C1, C2, C3, C4.
    """
    def __init__(self, data):
        self.raw_data = data
        self.type = data[0]
        self.size = 0
        self.content = b""
        self.decrypted_content = None
        self.parse_header()

    def parse_header(self):
        if self.type == 0xC1:
            self.size = self.raw_data[1]
            self.content = self.raw_data[2:]
        elif self.type == 0xC2:
            self.size = struct.unpack(">H", self.raw_data[1:3])[0]
            self.content = self.raw_data[3:]
        elif self.type == 0xC3:
            self.size = self.raw_data[1]
            self.content = self.raw_data[2:]
        elif self.type == 0xC4:
            self.size = struct.unpack(">H", self.raw_data[1:3])[0]
            self.content = self.raw_data[3:]
        else:
            # Unknown packet type
            self.size = len(self.raw_data)
            self.content = self.raw_data[1:]

    def get_opcode(self):
        """
        The opcode is usually the first byte of the content after the header.
        """
        if self.type in [0xC3, 0xC4] and self.decrypted_content:
            return self.decrypted_content[0]
            
        if len(self.content) > 0:
            return self.content[0]
        return None

    def try_decrypt(self, simple_mod):
        """
        Attempts to decrypt C3/C4 body using SimpleModulus.
        """
        if self.type in [0xC3, 0xC4]:
            # SimpleModulus logic processes blocks
            # We need to skip the header (2 bytes for C3, 3 for C4)
            data_to_decrypt = self.content
            # This is a conceptual integration
            try:
                # Mu packets are often XORed first, then SimpleModulus
                # For this PoC, we show where the hook goes
                pass
            except:
                pass

    def get_name(self):
        op = self.get_opcode()
        if op == 0xF4 and len(self.content) > 1:
            sub = self.content[1]
            if sub == 0x03: return "ConnectServer: Server Info (IP/Port)"
            if sub == 0x06: return "ConnectServer: Server List"
        return OPCODES.get(op, "Unknown")

    def modify_data(self, offset, new_bytes):
        """
        Modifies the raw data of the packet at a specific offset.
        """
        self.raw_data = self.raw_data[:offset] + new_bytes + self.raw_data[offset + len(new_bytes):]
        # Re-parse to update content/size if needed (though usually we don't change size here)
        self.parse_header()

    def __repr__(self):
        op = self.get_opcode()
        name = self.get_name()
        op_hex = hex(op) if op is not None else 'None'
        return f"Packet(Type={hex(self.type)}, Size={self.size}, OpCode={op_hex} [{name}])"

def parse_packets(stream):
    """
    Generator to extract packets from a byte stream.
    """
    while len(stream) > 0:
        p_type = stream[0]
        if p_type in [0xC1, 0xC3]:
            if len(stream) < 2: break
            p_size = stream[1]
        elif p_type in [0xC2, 0xC4]:
            if len(stream) < 3: break
            p_size = struct.unpack(">H", stream[1:3])[0]
        else:
            # Skip invalid byte
            stream = stream[1:]
            continue
        
        if len(stream) < p_size:
            break
            
        packet_data = stream[:p_size]
        yield Packet(packet_data)
        stream = stream[p_size:]
