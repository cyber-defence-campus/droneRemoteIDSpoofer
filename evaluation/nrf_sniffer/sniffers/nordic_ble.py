"""
Structured parser for Nordic BLE (DLT 272) frames of the nRF Sniffer for Bluetooth LE (UART
protocol 3), as nrfutil wrote them and nrf_uart.dlt_frame builds them:

    board (1) | payload length (2, LE) | protocol (1) | packet counter (2, LE) | packet id (1)
    event header: length (1, 10) | flags (1) | channel (1) | RSSI (1) | event counter (2) | timestamp (4)
    access address (4) | Coding Indicator (1, LE Coded PHY only) | PDU header (2) | PDU payload | CRC (3)

Flags: bit 0 CRC OK, bit 1 direction, bit 2 encrypted, bit 3 MIC OK, bits 4-6 PHY (0 1M, 1 2M,
2 Coded). RSSI holds the magnitude of a negative dBm value. Every field sits at a fixed offset or
follows from a length field; nothing is searched for.
"""

from dataclasses import dataclass
from typing import Optional

PROTOCOL_VERSION = 3
EVENT_PACKET_ADV_PDU = 0x02
EVENT_PACKET_DATA_PDU = 0x06
FIRMWARE_HEADER_END = 7  # board byte + 6-byte firmware packet header
MIN_EVENT_HEADER_LENGTH = 10
ACCESS_ADDRESS_LENGTH = 4
PDU_HEADER_LENGTH = 2
CRC_LENGTH = 3
ADVERTISING_ACCESS_ADDRESS = 0x8E89BED6

PHY_1M, PHY_2M, PHY_CODED = 0, 1, 2

# Advertising channel PDU types (Core Spec Vol 6 Part B 2.3), by the 4-bit type field
ADV_IND, ADV_DIRECT_IND, ADV_NONCONN_IND, SCAN_REQ, SCAN_RSP, CONNECT_IND, ADV_SCAN_IND, ADV_EXT_IND = range(8)
# Legacy PDUs whose payload starts with the advertiser address AdvA
LEGACY_PDUS_WITH_ADVA = (ADV_IND, ADV_DIRECT_IND, ADV_NONCONN_IND, SCAN_RSP, ADV_SCAN_IND)
# Legacy PDUs whose payload continues with advertising data after AdvA
LEGACY_PDUS_WITH_ADV_DATA = (ADV_IND, ADV_NONCONN_IND, SCAN_RSP, ADV_SCAN_IND)

# Common Extended Advertising Payload header flags (Core Spec Vol 6 Part B 2.3.4), in field order
EXT_ADVA, EXT_TARGETA, EXT_CTEINFO, EXT_ADI, EXT_AUXPTR, EXT_SYNCINFO, EXT_TXPOWER = (1 << i for i in range(7))
EXT_FIELD_LENGTHS = ((EXT_ADVA, 6), (EXT_TARGETA, 6), (EXT_CTEINFO, 1), (EXT_ADI, 2), (EXT_AUXPTR, 3),
                     (EXT_SYNCINFO, 18), (EXT_TXPOWER, 1))


@dataclass
class NordicBleFrame:
    """One parsed frame. Fields past a truncation are None or empty; truncated tells."""
    packet_id: int
    crc_ok: bool
    phy: int
    channel: int
    rssi_dbm: int
    event_counter: int
    timestamp_us: int
    access_address: int
    coding_indicator: Optional[int]
    pdu_type: int
    pdu_header: int  # both header bytes, LE (type, flags and length)
    payload: bytes  # PDU payload as received (at most the declared length)
    truncated: bool  # the frame ends before the declared PDU length and CRC

    @property
    def is_advertising(self) -> bool:
        return self.access_address == ADVERTISING_ACCESS_ADDRESS or self.packet_id == EVENT_PACKET_ADV_PDU

    @property
    def advertiser_address(self) -> Optional[bytes]:
        """AdvA as transmitted (little-endian), or None if the PDU carries none."""
        if self.pdu_type in LEGACY_PDUS_WITH_ADVA:
            return self.payload[0:6] if len(self.payload) >= 6 else None
        if self.pdu_type == ADV_EXT_IND:
            header = self.extended_header
            if header is not None and header[0] & EXT_ADVA and len(header) >= 7:
                return header[1:7]
        return None

    @property
    def extended_header(self) -> Optional[bytes]:
        """Flags byte and fields of an extended advertising PDU's header (without its length byte)."""
        if self.pdu_type != ADV_EXT_IND or not self.payload:
            return None
        length = self.payload[0] & 0x3F
        if length == 0 or len(self.payload) < 1 + length:
            return None
        return self.payload[1:1 + length]

    @property
    def advertising_data(self) -> Optional[bytes]:
        """The AD structures the PDU carries, or None if it carries none or is cut short."""
        if self.pdu_type in LEGACY_PDUS_WITH_ADV_DATA:
            return self.payload[6:] if len(self.payload) >= 6 else None
        if self.pdu_type == ADV_EXT_IND and self.payload:
            length = self.payload[0] & 0x3F
            if len(self.payload) < 1 + length:
                return None
            return self.payload[1 + length:]
        return None


def parse_frame(data: bytes) -> Optional[NordicBleFrame]:
    """
    Parses a Nordic BLE frame carrying a received radio packet. None for anything else: another
    protocol version, a packet that is not an advertising or data event, a declared length the
    data exceeds, or a frame cut before its PDU header.
    """
    if len(data) < FIRMWARE_HEADER_END or data[3] != PROTOCOL_VERSION:
        return None
    if len(data) > FIRMWARE_HEADER_END + int.from_bytes(data[1:3], "little"):
        return None
    packet_id = data[6]
    if packet_id not in (EVENT_PACKET_ADV_PDU, EVENT_PACKET_DATA_PDU) or len(data) <= FIRMWARE_HEADER_END:
        return None
    header_length = data[FIRMWARE_HEADER_END]
    if header_length < MIN_EVENT_HEADER_LENGTH:
        return None
    event = FIRMWARE_HEADER_END
    access = event + header_length
    if len(data) < access + ACCESS_ADDRESS_LENGTH:
        return None
    flags = data[event + 1]
    phy = (flags >> 4) & 0x07
    pdu = access + ACCESS_ADDRESS_LENGTH
    coding_indicator = None
    if phy == PHY_CODED:
        if len(data) <= pdu:
            return None
        coding_indicator = data[pdu]
        pdu += 1
    if len(data) < pdu + PDU_HEADER_LENGTH:
        return None
    pdu_header = int.from_bytes(data[pdu:pdu + PDU_HEADER_LENGTH], "little")
    declared = data[pdu + 1]
    payload_start = pdu + PDU_HEADER_LENGTH
    payload = data[payload_start:payload_start + declared]
    return NordicBleFrame(
        packet_id=packet_id,
        crc_ok=bool(flags & 0x01),
        phy=phy,
        channel=data[event + 2],
        rssi_dbm=-data[event + 3],
        event_counter=int.from_bytes(data[event + 4:event + 6], "little"),
        timestamp_us=int.from_bytes(data[access - 4:access], "little"),
        access_address=int.from_bytes(data[access:access + ACCESS_ADDRESS_LENGTH], "little"),
        coding_indicator=coding_indicator,
        pdu_type=data[pdu] & 0x0F,
        pdu_header=pdu_header,
        payload=payload,
        truncated=len(data) < payload_start + declared + CRC_LENGTH,
    )
