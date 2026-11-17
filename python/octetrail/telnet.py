"""Telnet, as dpkt 1.9.8 reads it.

:func:`strip_options` removes option negotiation from Telnet data in Rust.
"""

from . import _native

IAC = 255  # interpret as command
DONT = 254  # you are not to use option
DO = 253  # please, you use option
WONT = 252  # I won't use option
WILL = 251  # I will use option
SB = 250  # interpret as subnegotiation
GA = 249  # you may reverse the line
EL = 248  # erase the current line
EC = 247  # erase the current character
AYT = 246  # are you there
AO = 245  # abort output, but let the program finish
IP = 244  # interrupt process, permanently
BREAK = 243  # break
DM = 242  # data mark, for connect cleaning
NOP = 241  # nop
SE = 240  # end sub negotiation
EOR = 239  # end of record (transparent mode)
ABORT = 238  # abort process
SUSP = 237  # suspend process
xEOF = 236  # end of file: EOF is already used...

SYNCH = 242  # for telfunc calls

_SUBOPTIONS = (b"USER", b"DISPLAY", b"TERM")


def strip_options(buf):
    """Return a list of lines and dict of options from telnet data.

    As in dpkt, command bytes and suboption negotiation are dropped, NUL bytes
    end lines, and the USER, DISPLAY and TERM suboption values are collected.
    """
    # The same check as dpkt's first step, so other types fail the same way.
    buf.split(b"\xff", 0)
    raw = buf if type(buf) is bytes else bytes(buf)
    lines, options = _native._telnet_strip(raw)
    d = {}
    for index, start, end in options:
        d[_SUBOPTIONS[index]] = buf[start:end]
    return [buf[start:end] for start, end in lines], d
