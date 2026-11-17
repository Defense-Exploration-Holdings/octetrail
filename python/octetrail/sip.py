"""SIP requests and responses, parsed and packed the way dpkt 1.9.8 does.

As in dpkt, these are the HTTP classes with SIP's methods, protocol name and
default fields.
"""

from . import http


class Request(http.Request):
    """A SIP request: method, uri, version, headers, body and data."""

    __hdr_defaults__ = {
        "method": "INVITE",
        "uri": "sip:user@example.com",
        "version": "2.0",
        "headers": {"To": "", "From": "", "Call-ID": "", "CSeq": "", "Contact": ""},
    }
    __methods = dict.fromkeys(
        (
            "ACK",
            "BYE",
            "CANCEL",
            "INFO",
            "INVITE",
            "MESSAGE",
            "NOTIFY",
            "OPTIONS",
            "PRACK",
            "PUBLISH",
            "REFER",
            "REGISTER",
            "SUBSCRIBE",
            "UPDATE",
        )
    )
    __proto = "SIP"


class Response(http.Response):
    """A SIP response: version, status, reason, headers, body and data."""

    __hdr_defaults__ = {
        "version": "2.0",
        "status": "200",
        "reason": "OK",
        "headers": {"To": "", "From": "", "Call-ID": "", "CSeq": "", "Contact": ""},
    }
    __proto = "SIP"
