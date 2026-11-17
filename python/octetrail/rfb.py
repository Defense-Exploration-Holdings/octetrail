"""Remote Framebuffer protocol, as dpkt 1.9.8 reads it."""

from .packet import Packet

CLIENT_SET_PIXEL_FORMAT = 0
CLIENT_SET_ENCODINGS = 2
CLIENT_FRAMEBUFFER_UPDATE_REQUEST = 3
CLIENT_KEY_EVENT = 4
CLIENT_POINTER_EVENT = 5
CLIENT_CUT_TEXT = 6
SERVER_FRAMEBUFFER_UPDATE = 0
SERVER_SET_COLOUR_MAP_ENTRIES = 1
SERVER_BELL = 2
SERVER_CUT_TEXT = 3


class RFB(Packet):
    """RFB message type."""

    __hdr__ = (("type", "B", 0),)


class SetPixelFormat(Packet):
    """SetPixelFormat message."""

    __hdr__ = (("pad", "3s", b""), ("pixel_fmt", "16s", b""))


class SetEncodings(Packet):
    """SetEncodings message."""

    __hdr__ = (("pad", "1s", b""), ("num_encodings", "H", 0))


class FramebufferUpdateRequest(Packet):
    """FramebufferUpdateRequest message."""

    __hdr__ = (
        ("incremental", "B", 0),
        ("x_position", "H", 0),
        ("y_position", "H", 0),
        ("width", "H", 0),
        ("height", "H", 0),
    )


class KeyEvent(Packet):
    """KeyEvent message."""

    __hdr__ = (("down_flag", "B", 0), ("pad", "2s", b""), ("key", "I", 0))


class PointerEvent(Packet):
    """PointerEvent message."""

    __hdr__ = (("button_mask", "B", 0), ("x_position", "H", 0), ("y_position", "H", 0))


class FramebufferUpdate(Packet):
    """FramebufferUpdate message."""

    __hdr__ = (("pad", "1s", b""), ("num_rects", "H", 0))


class SetColourMapEntries(Packet):
    """SetColourMapEntries message."""

    __hdr__ = (("pad", "1s", b""), ("first_colour", "H", 0), ("num_colours", "H", 0))


class CutText(Packet):
    """CutText message."""

    __hdr__ = (("pad", "3s", b""), ("length", "I", 0))
