"""Bit-exact CPU twin of thresholds.v. v1.1 default values restored on reset."""
PORT_THRESH, HOST_THRESH, RATE_THRESH = 0x00, 0x01, 0x02
RULE_EPOCH = 0x03                                # v2 step 4: current rule_epoch; rules match only if their stored.epoch == this
_DEFAULTS = {PORT_THRESH: 5, HOST_THRESH: 5, RATE_THRESH: 8, RULE_EPOCH: 0}


class Thresholds:
    def __init__(self):
        self._v = dict(_DEFAULTS)

    def write(self, tid, value):
        """Unknown ids silently no-op, matching HDL (thresholds.v has a default case that
        does nothing). v2 audit MED #8 alignment."""
        if tid in _DEFAULTS:
            self._v[tid] = value & 0xFFFF

    def read(self, tid):
        """Unknown ids return 0, matching HDL's `default: r_val <= 16'd0`."""
        return self._v.get(tid, 0)
