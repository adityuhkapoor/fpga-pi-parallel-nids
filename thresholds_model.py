"""Bit-exact CPU twin of thresholds.v. v1.1 default values restored on reset."""
PORT_THRESH, HOST_THRESH, RATE_THRESH = 0x00, 0x01, 0x02
_DEFAULTS = {PORT_THRESH: 5, HOST_THRESH: 5, RATE_THRESH: 8}


class Thresholds:
    def __init__(self):
        self._v = dict(_DEFAULTS)

    def write(self, tid, value):
        if tid not in _DEFAULTS:
            raise KeyError(tid)
        self._v[tid] = value & 0xFFFF

    def read(self, tid):
        if tid not in _DEFAULTS:
            raise KeyError(tid)
        return self._v[tid]
