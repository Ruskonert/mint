"""
Determines AMS Protocol Specification.
Created By: Ruskonert (2023. 03. 24)
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
from scapy.layers.l2 import Ether
from scapy.contrib.ethercat import EtherCat


def AMS(*args, **kwargs):
    header = Beckhoff_AMS_TCP()
    ams = Beckhoff_AMS(*args, **kwargs)
    header.ams_length = ams.cbData + 32
    return header / ams



def AMS_L2(src, dst, *args, **kwargs):
    ams_ethercat = _ams_ethercat(src, dst)
    ams = Beckhoff_AMS(*args, **kwargs)
    ams_ethercat[EtherCat].length = len(ams)
    return ams_ethercat / ams



def Raw_IO(src, dst, *args, **kwargs):
    ethercat = _raw_io_ethercat(src, dst)
    raw_io = Beckhoff_RawIO(*args, **kwargs)
    ethercat[EtherCat].length = len(raw_io)
    return ethercat / raw_io



class Beckhoff_RawIO(Packet):
    name = "Raw_IO"
    fields_desc = [
        LEIntField("header", 0x00000000),
        FieldLenField("length", None, length_of="data"),
        StrLenField("data", b"", length_from=lambda pkt: pkt.length),
    ]
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "data" in kwargs:
            self.cbData = len(kwargs['data'])
            self.data = kwargs['data']



def _raw_io_ethercat(src, dst):
    ether = Ether(src=src, dst=dst, type=0x88a4)
    ethercat = EtherCat(type=0x03, length=0)
    return ether / ethercat



class Beckhoff_AMS_TCP(Packet):
    name = "AMS_TCP_HEADER"
    fields_desc = [
        LEShortField("tcp_resv", 0),
        LEIntField("ams_length", 0),
    ]



class Beckhoff_AMS(Packet):
    name = "AMS"
    fields_desc = [
        # Network
        StrFixedLenField("tNet_id", b"", 6),
        LEShortField("tport", 0x0001),
        StrFixedLenField("sNet_id", b"", 6),
        LEShortField("sport", 0x0002),
        LEShortField("cmdId", 0x0001),

        # StateFlags
        LEBitField("response", 0, 1),
        LEBitField("no_return", 0, 1),
        LEBitField("ads_command", 1, 1),
        LEBitField("system_command", 0, 1),
        LEBitField("high_prior_command", 0, 1),
        LEBitField("timestamp_added", 0, 1),
        LEBitField("udp_command", 0, 1),
        LEBitField("init_command", 0, 1),
        LEBitField("_resv2", 0, 7),
        LEBitField("broadcast", 0, 1),

        # length 
        LEIntField("cbData", 0),
        LEIntField("error", 0),
        LEIntField("invokeID", 0),

        StrLenField("data", b"", length_from=lambda pkt: pkt.length),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "tNet_id" in kwargs:
            self.tNet_id = struct.pack("<6B", *[int(x, 10) for x in kwargs['tNet_id'].split(".")])
        if "sNet_id" in kwargs:
            self.sNet_id = struct.pack("<6B", *[int(x, 10) for x in kwargs['sNet_id'].split(".")])
        if "data" in kwargs:
            self.cbData = len(kwargs['data'])
            self.data = kwargs['data']



def _ams_ethercat(src, dst):
    ether = Ether(src=src, dst=dst, type=0x88a4)
    ethercat = EtherCat(type=0x02, length=0)
    return ether / ethercat