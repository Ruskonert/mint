"""
Determines Lonworks (a.k.a, LON) Message Protocol Specification.
Created By: Ruskonert (2023. 04. 12)
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
import struct
import time
import math

LON_UDP_PORT = 1628
LON_UDP_URAGNT_PORT = 1629

"""
Determines Components Network over IP Frame (a.k.a, CN/IP).
"""
class CNIP(Packet):
    name = "CNIP"
    fields_desc = [
        ShortField("packet_length", 0),
        ByteField("version", 0x01),
        ByteField("packet_type", 0x01),
        ByteField("ext_header_size", 0),
        ByteField("flags", 0),
        ShortField("vendor_code", 0x00),
        IntField("session_id", 0x2e0487a0),
        IntField("seq", 0),
        # generated time
        IntField("timestamp", 0)
    ]

    def self_build(self):
        if self.timestamp == 0:
            self.timestamp = int(math.trunc(time.time()))
        return super().self_build()

    def post_build(self, pkt, pay):
        if self.packet_length == 0:
            pkt = struct.pack(">H", len(pkt + pay)) + pkt[2:]
        return super().post_build(pkt, pay)
    
"""
Determines Link-layer packet unit (LPDU) for LON Protocol.
When over the CN/IP Layer, it uses only LPDU in PPDU (Physical PDU) Layer.
"""
class LPDU(Packet):
    name = "LPDU"
    fields_desc = [
        # it means this packet is urgent case
        BitField("priority", 0, 1),
        BitField("alt_path", 0, 1),
        BitField("delta_bl", 0, 6),
    ]

# There are determined PDU Type in NPDU
LON_NPDU_PDU_TPDU = 0x00
LON_NPDU_PDU_SPDU = 0x01
LON_NPDU_PDU_AUTH_PDU = 0x02
LON_NPDU_PDU_APDU = 0x03

# There are pre-defined Address type in NPDU
LON_NPDU_ADDR_FORMAT_BROADCAST = 0x00
LON_NPDU_ADDR_FORMAT_MULTICAST = 0x01
LON_NPDU_ADDR_FORMAT_UNICAST_MULTICAST = 0x02
LON_NPDU_ADDR_FORMAT_UNICAST = 0x03

# There are pre-defined Domain type in NPDU
LON_NPDU_DOMAIN_LENGTH_CASE0 = 0x00
LON_NPDU_DOMAIN_LENGTH_CASE8 = 0x01
LON_NPDU_DOMAIN_LENGTH_CASE24 = 0x02
LON_NPDU_DOMAIN_LENGTH_CASE48 = 0x03

class NPDUAddressBroadcast(Packet):
    name = "NPDU_Broadcast"
    fields_desc = [
        ByteField("src_subnet", 1),
        BitField("_resv", 1, 1),
        BitField("src_node", 0, 7),
        ByteField("dst_subnet", 1),
    ]


class NPDUAddressMulticast(Packet):
    name = "NPDU_Multicast"
    fields_desc = [
        ByteField("src_subnet", 1),
        BitField("_resv", 1, 1),
        BitField("src_node", 0, 7),
        ByteField("dst_group", 0),
    ]


class NPDUAddressUnicastReminder(Packet):
    name = "NPDU_UnicastReminder"
    fields_desc = [
        ByteField("src_subnet", 1),
        BitField("_resv", 1, 1),
        BitField("src_node", 0, 7),
        ByteField("dst_subnet", 1),
        BitField("_resv2", 1, 1),
        BitField("dst_node", 0, 7),
    ]


class NPDUAddressMulticastAck(Packet):
    name = "NPDU_MulticastAck"
    fields_desc = [
        ByteField("src_subnet", 1),
        BitField("_resv", 0, 1),
        BitField("src_node", 0, 7),
        ByteField("dst_subnet", 1),
        BitField("_resv2", 1, 1),
        BitField("dst_node", 0, 7),
        ByteField("group", 0),
        ByteField("group_member", 0),
    ]


class NPDUAddressUnicast(Packet):
    name = "NPDU_Unicast"
    fields_desc = [
        ByteField("src_subnet", 0),
        BitField("_resv", 1, 1),
        BitField("src_node", 0, 7),
        ByteField("dst_subnet", 0),
        StrFixedLenField("neuron_id", 0, 6)
    ]


class NPDU(Packet):
    name = "NPDU"
    fields_desc = [
        BitField("version", 0, 2),
        # Don't worry, It will be filled by underlayer PDU
        BitField("pdu", None, 2),
        BitField("address_format", None, 2),
        BitField("domain_format", None, 2),
        PacketField("address", NPDUAddressUnicastReminder(), 
                    [NPDUAddressBroadcast, NPDUAddressMulticast, NPDUAddressUnicastReminder, NPDUAddressMulticastAck, NPDUAddressUnicast]),
        StrLenField("domain", "", length_from=lambda pkt:pkt.len)
    ]

    def self_build(self):
        if self.underlayer.haslayer(TPDU):
            self.pdu = LON_NPDU_PDU_TPDU
        elif self.underlayer.haslayer(SPDU):
            self.pdu = LON_NPDU_PDU_SPDU
        elif self.underlayer.haslayer(AuthPDU):
            self.pdu = LON_NPDU_PDU_AUTH_PDU
        else:
            # let's assume there is nothing of LON Layer
            self.pdu = LON_NPDU_PDU_APDU

        if self.address_format == None:
            if isinstance(self.address, NPDUAddressBroadcast):
                self.address_format = LON_NPDU_ADDR_FORMAT_BROADCAST
            elif isinstance(self.address, NPDUAddressMulticast):
                self.address_format = LON_NPDU_ADDR_FORMAT_MULTICAST
            elif isinstance(self.address, NPDUAddressUnicastReminder):
                self.address_format = LON_NPDU_ADDR_FORMAT_UNICAST_MULTICAST
            elif isinstance(self.address, NPDUAddressMulticastAck):
                self.address_format = LON_NPDU_ADDR_FORMAT_UNICAST_MULTICAST
            elif isinstance(self.address, NPDUAddressUnicast):
                self.address_format = LON_NPDU_ADDR_FORMAT_UNICAST
            else:
                raise Scapy_Exception("This address format is invaild")
        if self.domain_format == None:
            _domain_len = len(self.domain)
            if _domain_len == 0:
                self.domain_format = LON_NPDU_DOMAIN_LENGTH_CASE0
            elif _domain_len == 1:
                self.domain_format = LON_NPDU_DOMAIN_LENGTH_CASE8
            elif _domain_len == 3:
                self.domain_format = LON_NPDU_DOMAIN_LENGTH_CASE24
            elif _domain_len == 6:
                self.domain_format = LON_NPDU_DOMAIN_LENGTH_CASE48
            else:
                raise Scapy_Exception("This domain format is invaild, must be 0, 1, 3, 6 bytes")
        return super().self_build()

LON_TPDU_PDU_ACKD       = 0x00
LON_TPDU_PDU_UNACKD_RPT = 0x01
LON_TPDU_PDU_ACK        = 0x02
LON_TPDU_PDU_REMINDER   = 0x04
LON_TPDU_PDU_REM_MSG    = 0x05

class Reminder(Packet):
    name = "Reminder"
    fields_desc = [
        ByteEnumField("length", None, {0: "None", 24: "24 bits", 32: "32 bits", \
                                       40: "40 bits", 48: "48 bits", 56: "56 bits", 64: "64 bits"}),
        StrLenField("member_list", b"", length_from=lambda pkt:pkt.len)
    ]

    def self_build(self):
        if self.length == None:
            leng = len(self.member_list) * 8
            self.length = leng
        return super().self_build()

class ReminderMessage(Packet):
    name = "ReminderMessage"
    fields_desc = [
        ByteEnumField("length", None, {0: "None", 8: "8 bits", 16: "16 bits"}),
        StrLenField("member_list", b"", length_from=lambda pkt:pkt.len)
    ]
    
    def self_build(self):
        if self.length == None:
            leng = len(self.member_list) * 8
            self.length = leng
        return super().self_build()

class TPDU(Packet):
    name = "TPDU"
    fields_desc = [
        BitField("auth", 0, 1),
        BitField("pdu", None, 3),
        BitField("trans_number", 0, 4)
    ]

    def self_build(self):
        if self.pdu == None:
            if self.underlayer.haslayer(Reminder):
                self.pdu = LON_TPDU_PDU_REMINDER
            elif self.underlayer.haslayer(ReminderMessage):
                self.pdu = LON_TPDU_PDU_REM_MSG
            else:
                self.pdu = LON_TPDU_PDU_ACKD
        return super().self_build()
        
LON_SPDU_PDU_REQ       = 0x00
LON_SPDU_PDU_RESP      = 0x02
LON_SPDU_PDU_REMINDER  = 0x04
LON_SPDU_PDU_REM_MSG   = 0x05

class SPDU(Packet):
    name = "SPDU"
    fields_desc = [
        BitField("auth", 0, 1),
        # Don't worry, It will be filled by underlayer PDU
        BitField("pdu", None, 3),
        BitField("trans_number", 0, 4)
    ]

    def self_build(self):
        if self.pdu == None:
            if self.underlayer.haslayer(Reminder):
                self.pdu = LON_SPDU_PDU_REMINDER
            elif self.underlayer.haslayer(ReminderMessage):
                self.pdu = LON_SPDU_PDU_REM_MSG
            else:
                self.pdu = LON_SPDU_PDU_REQ
        return super().self_build()

"""
Not implemented.
"""
class AuthPDU(Packet):
    name = "AuthPDU"
    fields_desc = [

    ]

# That is same as request with no data (0b11)
LON_APDU_NVM_INCOMING = 0x03

# That is same as response with data (0b10)
LON_APDU_NVM_OUTCOMING = 0x02

class APDUNetworkVariableMessage(Packet):
    name = "APDU_NVM"
    fields_desc = [
        BitEnumField("destin", LON_APDU_NVM_INCOMING, 2, {LON_APDU_NVM_OUTCOMING: "Outcoming", LON_APDU_NVM_INCOMING: "Incoming"}),
        BitField("selector", 0x00, 14)
    ]

LON_APDU_NMM_REQUEST = 0x01
LON_APDU_NMM_RESPONSE = 0x00

LON_APDU_NMM_STATUS_FAILED = 0x00
LON_APDU_NMM_STATUS_RESV_OR_SUCCESS = 0x01

class APDUNetworkManagementMessage(Packet):
    name = "APDU_NMM"
    fields_desc = [
        BitEnumField("destin", LON_APDU_NMM_REQUEST, 2, {LON_APDU_NMM_REQUEST: "Request", LON_APDU_NMM_RESPONSE: "Response"}),
        BitField("status", LON_APDU_NMM_STATUS_RESV_OR_SUCCESS, 1),
        BitField("function", 0x0, 5)
    ]

    def self_build(self):
        if self.destin == LON_APDU_NMM_REQUEST:
            if self.status == LON_APDU_NMM_STATUS_FAILED:
                raise Scapy_Exception("Cannot assigned zero-value when REQ!")
        return super().self_build()

LON_APDU_NDM_REQUEST = 0x01
LON_APDU_NDM_RESPONSE = 0x01

LON_APDU_NDM_STATUS_FAILED = 0x03
LON_APDU_NDM_STATUS_RESV_OR_SUCCESS = 0x01

class APDUNetworkDiagnosticMessage(Packet):
    name = "APDU_NDM"
    fields_desc = [
        BitEnumField("destin", LON_APDU_NDM_REQUEST, 2, {LON_APDU_NDM_REQUEST: "Request", LON_APDU_NDM_RESPONSE: "Response"}),
        BitField("status", LON_APDU_NDM_STATUS_RESV_OR_SUCCESS, 2),
        BitField("function", 0x0, 4)
    ]

    def self_build(self):
        if self.destin == LON_APDU_NDM_REQUEST:
            if self.status == LON_APDU_NDM_STATUS_FAILED:
                raise Scapy_Exception("Cannot assigned zero-value when REQ!")
        return super().self_build()

class APDU(Packet):
    name = "APDU"
    fields_desc = [
        PacketField("apdu", APDUNetworkVariableMessage(), [APDUNetworkVariableMessage,
                                                           APDUNetworkManagementMessage,
                                                           APDUNetworkDiagnosticMessage]),
        StrLenField("data", b'', length_from=lambda pkt: pkt.len)
    ]


