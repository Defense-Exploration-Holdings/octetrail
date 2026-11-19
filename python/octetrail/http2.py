"""HTTP/2 frames (RFC 7540), as dpkt 1.9.8 reads them.

The frames use the :class:`octetrail.Packet` base. ``frame_multi_factory``
finds frame boundaries in Rust. The constants, classes and helpers are dpkt's.
"""

import struct

from . import _native
from .errors import NeedData, UnpackError
from .packet import Packet

HTTP2_PREFACE = b"\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a"

# Frame types
HTTP2_FRAME_DATA = 0
HTTP2_FRAME_HEADERS = 1
HTTP2_FRAME_PRIORITY = 2
HTTP2_FRAME_RST_STREAM = 3
HTTP2_FRAME_SETTINGS = 4
HTTP2_FRAME_PUSH_PROMISE = 5
HTTP2_FRAME_PING = 6
HTTP2_FRAME_GOAWAY = 7
HTTP2_FRAME_WINDOW_UPDATE = 8
HTTP2_FRAME_CONTINUATION = 9

# Flags
HTTP2_FLAG_END_STREAM = 0x01  # for DATA and HEADERS frames
HTTP2_FLAG_ACK = 0x01  # for SETTINGS and PING frames
HTTP2_FLAG_END_HEADERS = 0x04
HTTP2_FLAG_PADDED = 0x08
HTTP2_FLAG_PRIORITY = 0x20

# Settings
HTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x1
HTTP2_SETTINGS_ENABLE_PUSH = 0x2
HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
HTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4
HTTP2_SETTINGS_MAX_FRAME_SIZE = 0x5
HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

# Error codes
HTTP2_NO_ERROR = 0x0
HTTP2_PROTOCOL_ERROR = 0x1
HTTP2_INTERNAL_ERROR = 0x2
HTTP2_FLOW_CONTROL_ERROR = 0x3
HTTP2_SETTINGS_TIMEOUT = 0x4
HTTP2_STREAM_CLOSED = 0x5
HTTP2_FRAME_SIZE_ERROR = 0x6
HTTP2_REFUSED_STREAM = 0x7
HTTP2_CANCEL = 0x8
HTTP2_COMPRESSION_ERROR = 0x9
HTTP2_CONNECT_ERROR = 0xA
HTTP2_ENHANCE_YOUR_CALM = 0xB
HTTP2_INADEQUATE_SECURITY = 0xC
HTTP2_HTTP_1_1_REQUIRED = 0xD

error_code_str = {
    HTTP2_NO_ERROR: "NO_ERROR",
    HTTP2_PROTOCOL_ERROR: "PROTOCOL_ERROR",
    HTTP2_INTERNAL_ERROR: "INTERNAL_ERROR",
    HTTP2_FLOW_CONTROL_ERROR: "FLOW_CONTROL_ERROR",
    HTTP2_SETTINGS_TIMEOUT: "SETTINGS_TIMEOUT",
    HTTP2_STREAM_CLOSED: "STREAM_CLOSED",
    HTTP2_FRAME_SIZE_ERROR: "FRAME_SIZE_ERROR",
    HTTP2_REFUSED_STREAM: "REFUSED_STREAM",
    HTTP2_CANCEL: "CANCEL",
    HTTP2_COMPRESSION_ERROR: "COMPRESSION_ERROR",
    HTTP2_CONNECT_ERROR: "CONNECT_ERROR",
    HTTP2_ENHANCE_YOUR_CALM: "ENHANCE_YOUR_CALM",
    HTTP2_INADEQUATE_SECURITY: "INADEQUATE_SECURITY",
    HTTP2_HTTP_1_1_REQUIRED: "HTTP_1_1_REQUIRED",
}


class HTTP2Exception(UnpackError):
    """An invalid HTTP/2 frame or preface.

    dpkt derives this class from Exception only. Here it is also an
    UnpackError, so code that catches parse errors handles it.
    """


class Preface(Packet):
    __hdr__ = (("preface", "24s", HTTP2_PREFACE),)

    def unpack(self, buf):
        Packet.unpack(self, buf)
        if self.preface != HTTP2_PREFACE:
            raise HTTP2Exception("Invalid HTTP/2 preface")
        self.data = ""


class Frame(Packet):
    """
    An HTTP/2 frame as defined in RFC 7540
    """

    # struct.unpack can't handle the 3-byte int, so we parse it as bytes
    # (and store it as bytes so dpkt doesn't get confused), and turn it into
    # an int in a user-facing property
    __hdr__ = (
        ("length_bytes", "3s", b"\x00\x00\x00"),
        ("type", "B", 0),
        ("flags", "B", 0),
        ("stream_id", "I", 0),
    )

    def unpack(self, buf):
        Packet.unpack(self, buf)
        # only take the right number of bytes
        self.data = self.data[: self.length]
        if len(self.data) != self.length:
            raise NeedData

    @property
    def length(self):
        return struct.unpack("!I", b"\x00" + self.length_bytes)[0]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # A frame built from fields gets a zero length filled in on pack. A
        # parsed frame packs back to its own bytes.
        self._fill_on_pack = not args

    def pack_hdr(self):
        if self._fill_on_pack and self.length_bytes == b"\x00\x00\x00" and len(self.data):
            self.length_bytes = struct.pack("!I", len(self.data))[1:]
        return Packet.pack_hdr(self)


class Priority(Packet):
    """
    Payload of a PRIORITY frame, also used in HEADERS frame with FLAG_PRIORITY.

    Also used in the HEADERS frame if the PRIORITY flag is set.
    """

    __hdr__ = (
        ("stream_dep", "I", 0),
        ("weight", "B", 0),
    )

    def unpack(self, buf):
        Packet.unpack(self, buf)
        if len(self.data) != 0:
            raise HTTP2Exception("Invalid number of bytes in PRIORITY frame")
        self.exclusive = (self.stream_dep & 0x80000000) != 0
        self.stream_dep &= 0x7FFFFFFF
        self.weight += 1


class Setting(Packet):
    """
    A key-value pair used in the SETTINGS frame.
    """

    __hdr__ = (
        ("identifier", "H", 0),
        ("value", "I", 0),
    )


class PaddedFrame(Frame):
    """
    Abstract class for frame types that support the FLAG_PADDED flag: DATA,
    HEADERS and PUSH_PROMISE.
    """

    def unpack(self, buf):
        Frame.unpack(self, buf)
        if self.flags & HTTP2_FLAG_PADDED:
            if self.length == 0:
                raise HTTP2Exception("Missing padding length in PADDED frame")
            self.pad_length = struct.unpack("B", self.data[0:1])[0]
            if self.length <= self.pad_length:
                raise HTTP2Exception("Missing padding bytes in PADDED frame")
            self.unpadded_data = self.data[1 : -self.pad_length]
        else:
            self.unpadded_data = self.data


class DataFrame(PaddedFrame):
    """
    Frame of type DATA.
    """

    @property
    def payload(self):
        return self.unpadded_data


class HeadersFrame(PaddedFrame):
    """
    Frame of type HEADERS.
    """

    def unpack(self, buf):
        PaddedFrame.unpack(self, buf)
        if self.flags & HTTP2_FLAG_PRIORITY:
            if len(self.unpadded_data) < 5:
                raise HTTP2Exception(
                    "Missing stream dependency in HEADERS frame with PRIORITY flag"
                )
            self.priority = Priority(self.unpadded_data[:5])
            self.block_fragment = self.unpadded_data[5:]
        else:
            self.block_fragment = self.unpadded_data


class PriorityFrame(Frame):
    """
    Frame of type PRIORITY.
    """

    def unpack(self, buf):
        Frame.unpack(self, buf)
        self.priority = Priority(self.data)


class RSTStreamFrame(Frame):
    """
    Frame of type RST_STREAM.
    """

    def unpack(self, buf):
        Frame.unpack(self, buf)
        if self.length != 4:
            raise HTTP2Exception("Invalid number of bytes in RST_STREAM frame (must be 4)")
        self.error_code = struct.unpack("!I", self.data)[0]


class SettingsFrame(Frame):
    """
    Frame of type SETTINGS.
    """

    def unpack(self, buf):
        Frame.unpack(self, buf)
        if self.length % 6 != 0:
            raise HTTP2Exception(
                "Invalid number of bytes in SETTINGS frame (must be multiple of 6)"
            )
        self.settings = []
        i = 0
        while i < self.length:
            self.settings.append(Setting(self.data[i : i + 6]))
            i += 6


class PushPromiseFrame(PaddedFrame):
    """
    Frame of type PUSH_PROMISE.
    """

    def unpack(self, buf):
        PaddedFrame.unpack(self, buf)
        if len(self.unpadded_data) < 4:
            raise HTTP2Exception("Missing promised stream ID in PUSH_PROMISE frame")
        self.promised_id = struct.unpack("!I", self.data[:4])[0]
        self.block_fragment = self.unpadded_data[4:]


class PingFrame(Frame):
    """
    Frame of type PING.
    """

    def unpack(self, buf):
        Frame.unpack(self, buf)
        if self.length != 8:
            raise HTTP2Exception("Invalid number of bytes in PING frame (must be 8)")


class GoAwayFrame(Frame):
    """
    Frame of type GO_AWAY.
    """

    def unpack(self, buf):
        Frame.unpack(self, buf)
        if self.length < 8:
            raise HTTP2Exception("Invalid number of bytes in GO_AWAY frame")
        self.last_stream_id = struct.unpack("!I", self.data[:4])[0]
        self.error_code = struct.unpack("!I", self.data[4:8])[0]
        self.debug_data = self.data[8:]


class WindowUpdateFrame(Frame):
    """
    Frame of type WINDOW_UPDATE.
    """

    def unpack(self, buf):
        Frame.unpack(self, buf)
        if self.length != 4:
            raise HTTP2Exception("Invalid number of bytes in WINDOW_UPDATE frame (must be 4)")
        self.window_increment = struct.unpack("!I", self.data)[0]


class ContinuationFrame(Frame):
    """
    Frame of type CONTINUATION.
    """

    def unpack(self, buf):
        Frame.unpack(self, buf)
        self.block_fragment = self.data


FRAME_TYPES = {
    HTTP2_FRAME_DATA: ("DATA", DataFrame),
    HTTP2_FRAME_HEADERS: ("HEADERS", HeadersFrame),
    HTTP2_FRAME_PRIORITY: ("PRIORITY", PriorityFrame),
    HTTP2_FRAME_RST_STREAM: ("RST_STREAM", RSTStreamFrame),
    HTTP2_FRAME_SETTINGS: ("SETTINGS", SettingsFrame),
    HTTP2_FRAME_PUSH_PROMISE: ("PUSH_PROMISE", PushPromiseFrame),
    HTTP2_FRAME_PING: ("PING", PingFrame),
    HTTP2_FRAME_GOAWAY: ("GOAWAY", GoAwayFrame),
    HTTP2_FRAME_WINDOW_UPDATE: ("WINDOW_UPDATE", WindowUpdateFrame),
    HTTP2_FRAME_CONTINUATION: ("CONTINUATION", ContinuationFrame),
}


class FrameFactory(object):
    def __new__(cls, buf):
        if len(buf) < 4:
            raise NeedData
        t = struct.unpack("B", buf[3:4])[0]
        frame_type = FRAME_TYPES.get(t)
        if frame_type is None:
            raise HTTP2Exception("Invalid frame type: " + hex(t))
        return frame_type[1](buf)


def frame_multi_factory(buf, preface=False):
    """
    Attempt to parse one or more Frame's out of buf

    Args:
      buf: string containing HTTP/2 frames. May have an incomplete frame at the
        end.
      preface: expect an HTTP/2 preface at the beginning of the buffer.

    Returns:
      [Frame]
      int, total bytes consumed, != len(buf) if an incomplete frame was left at
        the end.
    """
    i = 0
    n = len(buf)
    frames = []

    if preface:
        try:
            p = Preface(buf)
            i += len(p)
        except NeedData:
            return [], 0

    # The whole frames are found in Rust, and each is built from its own bytes.
    spans, tail = _native._http2_frame_spans(bytes(buf), i)
    for start, end in spans:
        try:
            frame = FrameFactory(buf[start:end])
        except NeedData:
            return frames, i
        frames.append(frame)
        i += len(frame)
    if tail < n:
        try:
            frame = FrameFactory(buf[tail:])
            frames.append(frame)
            i += len(frame)
        except NeedData:
            pass
    return frames, i
