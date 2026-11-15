#!/usr/bin/env python3
"""Verify the manual-NAN Discovery-Window airtime model against a real capture.

Reads a classic pcap (as written by `tcpdump -w`) of injected NAN frames,
extracts per-frame radiotap TSFT (us), PHY rate and 802.11 length, and compares
the MEASURED on-air time of each Service Discovery Frame against the model used
by NanManualBackend:  airtime_us = 20 (OFDM preamble) + bytes*8/rate + 10 (IFS).

It answers the three things the offline length check cannot:
  1. did the NIC actually transmit at the requested 6 Mbps? (radiotap rate)
  2. what is the real per-SDF on-air length incl. hardware FCS?
  3. what is the real back-to-back SDF spacing (TSFT deltas) vs the 394 us model?

No scapy / tshark needed. Self-contained radiotap + 802.11 parser.

Usage: python3 verify_nan_airtime.py <capture.pcap> [cluster_bssid]
       default cluster_bssid = 50:6f:9a:01:00:ff
"""
import statistics
import struct
import sys

PREAMBLE_US, IFS_US = 20.0, 10.0  # same constants as NanManualBackend
DW_US, OFFSET_US = 16384.0, 300.0

# radiotap field (align, size) by present-bit, enough to walk up to the ones we need
_RT_FIELDS = {
    0: (8, 8),   # TSFT (u64 us)
    1: (1, 1),   # Flags
    2: (1, 1),   # Rate (500 kbps units)
    3: (2, 4),   # Channel
    4: (2, 2),   # FHSS
    5: (1, 1),   # dBm antenna signal
    6: (1, 1),   # dBm antenna noise
    7: (2, 2),   # lock quality
    8: (2, 2),   # tx attenuation
    9: (2, 2),   # dB tx attenuation
    10: (1, 1),  # dBm tx power
    11: (1, 1),  # antenna
    12: (1, 1),  # dB antenna signal
    13: (1, 1),  # dB antenna noise
    14: (2, 2),  # rx flags
    15: (2, 2),  # tx flags
    16: (1, 1),  # rts retries
    17: (1, 1),  # data retries
    18: (4, 8),  # xchannel
    19: (1, 3),  # MCS
    20: (4, 8),  # A-MPDU
    21: (2, 12), # VHT
}
_RT_FLAG_FCS = 0x10  # radiotap Flags: FCS at end of frame


def _parse_radiotap(pkt):
    """Return (rt_len, tsft_us_or_None, rate_mbps_or_None, fcs_present)."""
    if len(pkt) < 8:
        return None
    _, _, rt_len = struct.unpack_from("<BBH", pkt, 0)
    # collect all present words (handle the Ext bit chain)
    present_words, off = [], 4
    while off + 4 <= len(pkt):
        w = struct.unpack_from("<I", pkt, off)[0]
        present_words.append(w)
        off += 4
        if not (w & (1 << 31)):
            break
    data = off
    tsft = rate = None
    fcs = False
    for bit, (align, size) in _RT_FIELDS.items():
        word, b = present_words[bit // 32] if bit // 32 < len(present_words) else 0, bit % 32
        if bit // 32 >= len(present_words) or not (word & (1 << b)):
            continue
        if data % align:
            data += align - (data % align)
        if data + size > rt_len:
            break
        if bit == 0:
            tsft = struct.unpack_from("<Q", pkt, data)[0]
        elif bit == 1:
            fcs = bool(pkt[data] & _RT_FLAG_FCS)
        elif bit == 2:
            rate = pkt[data] * 0.5
        data += size
    return rt_len, tsft, rate, fcs


def _frames(path, cluster):
    buf = open(path, "rb").read()
    magic = struct.unpack_from("<I", buf, 0)[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        endian, nano = "<", magic == 0xA1B23C4D
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        endian, nano = ">", magic == 0x4D3CB2A1
    else:
        sys.exit(f"not a classic pcap (magic {magic:#x}); use `tcpdump -w`, not pcapng")
    off = 24
    while off + 16 <= len(buf):
        ts_s, ts_f, caplen, _ = struct.unpack_from(endian + "IIII", buf, off)
        off += 16
        pkt = buf[off:off + caplen]
        off += caplen
        rt = _parse_radiotap(pkt)
        if not rt:
            continue
        rt_len, tsft, rate, fcs = rt
        d = pkt[rt_len:]
        if len(d) < 24:
            continue
        fc = d[0]
        subtype = (fc >> 2 & 3, fc >> 4 & 0xF)  # (type, subtype)
        addr3 = d[16:22]
        if addr3 != cluster:
            continue
        over_air = len(d)                 # 802.11 incl. FCS if hardware appended it
        pcap_ts = ts_s + ts_f * (1e-9 if nano else 1e-6)
        yield subtype, d[10:16], over_air, tsft, rate, pcap_ts


def airtime(nbytes, rate):
    return PREAMBLE_US + (nbytes * 8.0) / rate + IFS_US


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    cluster = bytes.fromhex((sys.argv[2] if len(sys.argv) > 2
                             else "50:6f:9a:01:00:ff").replace(":", ""))

    sdf_lens, rates, tsfts = [], [], []
    beacon_lens = []
    n_tsft = n_total = 0
    for (typ, sub), src, over_air, tsft, rate, pcap_ts in _frames(path, cluster):
        n_total += 1
        if tsft is not None:
            n_tsft += 1
        if (typ, sub) == (0, 13):          # public action = SDF
            sdf_lens.append(over_air)
            if rate:
                rates.append(rate)
            if tsft is not None:
                tsfts.append(tsft)
        elif (typ, sub) == (0, 8):         # beacon
            beacon_lens.append(over_air)

    if n_total == 0:
        sys.exit("no frames matched the cluster BSSID; check the channel / filter")

    print(f"frames matched cluster {cluster.hex(':')}: {n_total} "
          f"(SDF={len(sdf_lens)}, beacon={len(beacon_lens)})")
    print(f"radiotap TSFT present on {n_tsft}/{n_total} frames")
    print()

    if rates:
        rset = sorted(set(rates))
        print(f"PHY rate (radiotap): {rset} Mbps  "
              f"(expect [6.0] if the 6 Mbps floor took effect on air)")
    else:
        print("PHY rate: NOT reported by radiotap (driver omits the Rate field; "
              "try MCS/VHT fields or a different sniffer)")
    print()

    if sdf_lens:
        med = statistics.median(sdf_lens)
        r = statistics.median(rates) if rates else 6.0
        print(f"SDF on-air length: min={min(sdf_lens)} median={med:.0f} "
              f"max={max(sdf_lens)} bytes  (built=273 B + 4 B FCS => expect ~277)")
        print(f"  modeled airtime  @ {r} Mbps: {airtime(med, r):.1f} us "
              f"(273 B nominal -> {airtime(273, r):.1f} us)")
        if len(tsfts) >= 3:
            tsfts.sort()
            deltas = [b - a for a, b in zip(tsfts, tsfts[1:]) if 0 < b - a < 5000]
            if deltas:
                dmed = statistics.median(deltas)
                print(f"  MEASURED back-to-back SDF spacing (TSFT delta): "
                      f"median={dmed:.1f} us  min={min(deltas):.1f} "
                      f"max={max(deltas):.1f}  n={len(deltas)}")
                print(f"  -> ratio measured/model = {dmed / airtime(med, r):.2f} "
                      f"(>1 means the driver adds gaps; model is optimistic)")
                cap = int((DW_US - OFFSET_US - (airtime(statistics.median(beacon_lens), r)
                           if beacon_lens else airtime(106, r))) // dmed)
                print(f"  -> real DW capacity at measured spacing: ~{cap} SDFs "
                      f"(model says ~40 at 6 Mbps)")
            else:
                print("  (no usable TSFT deltas; frames may be from different bursts)")
        else:
            print("  (insufficient TSFT timestamps for spacing measurement)")
    if beacon_lens:
        print(f"Beacon on-air length: median={statistics.median(beacon_lens):.0f} bytes "
              f"(built=106 B + 4 B FCS => expect ~110)")


if __name__ == "__main__":
    main()
