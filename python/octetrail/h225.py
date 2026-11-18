"""ITU-T H.225.0 call signaling, as dpkt 1.9.8 reads and writes it.

``H225`` and ``H225.IE`` use the :class:`octetrail.Packet` base, and the
message is read from inside a TPKT header, as in dpkt. The information element
boundaries are found in Rust. The constants are dpkt's.
"""

import struct

from . import _native, tpkt
from .errors import UnpackError
from .packet import Packet

# Call messages and information elements (IEs) are defined by Q.931. The
# User-to-User IEs of H.225 are encoded by PER of ASN.1.

# Call Establishment Messages
ALERTING = 1
CALL_PROCEEDING = 2
CONNECT = 7
CONNECT_ACKNOWLEDGE = 15
PROGRESS = 3
SETUP = 5
SETUP_ACKNOWLEDGE = 13

# Call Information Phase Messages
RESUME = 38
RESUME_ACKNOWLEDGE = 46
RESUME_REJECT = 34
SUSPEND = 37
SUSPEND_ACKNOWLEDGE = 45
SUSPEND_REJECT = 33
USER_INFORMATION = 32

# Call Clearing Messages
DISCONNECT = 69
RELEASE = 77
RELEASE_COMPLETE = 90
RESTART = 70
RESTART_ACKNOWLEDGE = 78

# Miscellaneous Messages
SEGMENT = 96
CONGESTION_CONTROL = 121
INFORMATION = 123
NOTIFY = 110
STATUS = 125
STATUS_ENQUIRY = 117

# Type 1 Single Octet Information Element IDs
RESERVED = 128
SHIFT = 144
CONGESTION_LEVEL = 176
REPEAT_INDICATOR = 208

# Type 2 Single Octet Information Element IDs
MORE_DATA = 160
SENDING_COMPLETE = 161

# Variable Length Information Element IDs
SEGMENTED_MESSAGE = 0
BEARER_CAPABILITY = 4
CAUSE = 8
CALL_IDENTITY = 16
CALL_STATE = 20
CHANNEL_IDENTIFICATION = 24
PROGRESS_INDICATOR = 30
NETWORK_SPECIFIC_FACILITIES = 32
NOTIFICATION_INDICATOR = 39
DISPLAY = 40
DATE_TIME = 41
KEYPAD_FACILITY = 44
SIGNAL = 52
INFORMATION_RATE = 64
END_TO_END_TRANSIT_DELAY = 66
TRANSIT_DELAY_SELECTION_AND_INDICATION = 67
PACKET_LAYER_BINARY_PARAMETERS = 68
PACKET_LAYER_WINDOW_SIZE = 69
PACKET_SIZE = 70
CLOSED_USER_GROUP = 71
REVERSE_CHARGE_INDICATION = 74
CALLING_PARTY_NUMBER = 108
CALLING_PARTY_SUBADDRESS = 109
CALLED_PARTY_NUMBER = 112
CALLED_PARTY_SUBADDRESS = 113
REDIRECTING_NUMBER = 116
TRANSIT_NETWORK_SELECTION = 120
RESTART_INDICATOR = 121
LOW_LAYER_COMPATIBILITY = 124
HIGH_LAYER_COMPATIBILITY = 125
USER_TO_USER = 126
ESCAPE_FOR_EXTENSION = 127


class H225(Packet):
    """An H.225.0 call signaling message inside its TPKT header.

    Attributes:
        proto: Protocol discriminator.
        ref_len: Length of the call reference value.
        tpkt: The TPKT header the message was read from.
        ref_val: The call reference value.
        type: The message type.
        data: A list of :class:`H225.IE` information elements.
    """

    __hdr__ = (("proto", "B", 8), ("ref_len", "B", 2))

    def unpack(self, buf):
        self.tpkt = tpkt.TPKT(buf)
        if self.tpkt.v != 3:
            raise UnpackError("invalid TPKT version")
        if self.tpkt.rsvd != 0:
            raise UnpackError("invalid TPKT reserved value")
        n = self.tpkt.len - self.tpkt.__hdr_len__
        if n > len(self.tpkt.data):
            raise UnpackError("invalid TPKT length")
        buf = self.tpkt.data

        Packet.unpack(self, buf)
        buf = buf[self.__hdr_len__ :]
        self.ref_val = buf[: self.ref_len]
        buf = buf[self.ref_len :]
        self.type = struct.unpack("B", buf[:1])[0]
        buf = buf[1:]

        spans, cut = _native._h225_elements(bytes(buf))
        elements = [self.IE(buf[start:end]) for start, end in spans]
        if cut is not None:
            elements.append(self.IE(buf[cut:]))
        self.data = elements

    def __len__(self):
        return self.tpkt.__hdr_len__ + self.__hdr_len__ + sum(map(len, self.data))

    def __bytes__(self):
        return (
            self.tpkt.pack_hdr()
            + self.pack_hdr()
            + self.ref_val
            + struct.pack("B", self.type)
            + b"".join(map(bytes, self.data))
        )

    class IE(Packet):
        """An information element: a type, a length unless the type's high bit is
        set, and a value.
        """

        __hdr__ = (("type", "B", 0),)

        def unpack(self, buf):
            Packet.unpack(self, buf)
            buf = buf[self.__hdr_len__ :]

            if self.type & 0x80:
                self.len = 0
                self.data = b""
            else:
                if self.type == USER_TO_USER:
                    self.len = struct.unpack(">H", buf[:2])[0]
                    buf = buf[2:]
                else:
                    self.len = struct.unpack("B", buf[:1])[0]
                    buf = buf[1:]
                self.data = buf[: self.len]

        def __len__(self):
            if self.type & 0x80:
                n = 0
            elif self.type == USER_TO_USER:
                n = 2
            else:
                n = 1
            return self.__hdr_len__ + self.len + n

        def __bytes__(self):
            if self.type & 0x80:
                length_str = b""
            elif self.type == USER_TO_USER:
                length_str = struct.pack(">H", self.len)
            else:
                length_str = struct.pack("B", self.len)
            return struct.pack("B", self.type) + length_str + self.data
