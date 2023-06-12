"""
Determines TSAA Specification whch is part of TriStation Protocol.
Created By: Ruskonert (2023. 04. 17)
"""

"""
MIT License

Copyright (c) 2023 ruskonert@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from scapy.all import *

"""
The flag field is a bit field that indicates the position of 
the frame in a multi-frame message, or that the message is 
a single frame.
"""
TSAA_FLAG_DESC = { 0x00: "Mid-frame", 
                  0x01: "First or Last-Frame",
                  0x03: "Single-Frame"}


class TSAABinaryHeader(Packet):
    name = "TSAABinaryHeader"
    fields_desc = [
       ByteField("binary", 0),
       ByteField("resv", 0),
       ShortField("total_length", 0),
       ShortField("offset", 0),
       ShortField("length", 0),
       StrLenField("data", b'', length_from=lambda pkt: pkt.len)
    ]

    def build_done(self, p):
       total_length = struct.pack(">H", len(p))
       payload = p[:2] + total_length + p[4:]
       return super().build_done(payload)

    def self_build(self):
       self.length = len(self.data)
       return super().self_build()


class TSAA(Packet):
    name = "TSAA"
    fields_desc = [
        ByteField("type", 0x00),
        ByteField("node_number", 0),
        ByteField("seq", 0),
        # identifies the version number of the protocol 
        # used by the sender. For a Tricon system, the number must be 0.
        ByteField("version", 0x00),
        ByteEnumField("flag", 0x03, TSAA_FLAG_DESC),
        ByteField("id", 0),
        ShortField("length", 0),
        StrLenField("data", b'', length_from=lambda pkt: pkt.len),
        # will be filled automatically
        LEIntField("crc", 0)
    ]

    def self_build(self) -> bytes:
        if self.data != None and len(self.data) != 0:
            self.length = len(self.data) + 12
            if self.crc == 0:
                self.crc = TSAA.crc32(0, bytes(self.data), len(self.data))
        return super().self_build()
    
    @staticmethod
    def crc32(crc, p, len):
      crc = 0xffffffff & ~crc
      for i in range(len):
        crc = crc ^ p[i]
        for _ in range(8):
          crc = (crc >> 1) ^ (0xedb88320 & -(crc & 1))
      return 0xffffffff & ~crc
