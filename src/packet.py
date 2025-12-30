import struct

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
        if len(self.content) > 0:
            return self.content[0]
        return None

    def __repr__(self):
        return f"Packet(Type={hex(self.type)}, Size={self.size}, OpCode={hex(self.get_opcode()) if self.get_opcode() is not None else 'None'})"

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
