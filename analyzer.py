from scapy.all import rdpcap, IP, ESP, UDP, ISAKMP
import struct


IKE_EXCHANGES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL"
}

ENCRYPTION_ALGORITHMS = {
    1: "DES-IV64",
    2: "3DES",
    3: "RC5",
    4: "IDEA",
    5: "CAST",
    6: "BLOWFISH",
    7: "3IDEA",
    8: "DES",
    9: "AES-CBC",
    10: "AES-CTR",
    11: "AES-CCM",
    12: "AES-GCM",
    13: "CAMELLIA",
}

INTEGRITY_ALGORITHMS = {
    1: "HMAC-MD5-96",
    2: "HMAC-SHA1-96",
    5: "AES-XCBC-96",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256",
}

PRF_ALGORITHMS = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    4: "AES128-XCBC",
    5: "HMAC-SHA2-256",
    6: "HMAC-SHA2-384",
    7: "HMAC-SHA2-512",
}

DH_GROUPS = {
    1: "MODP768",
    2: "MODP1024",
    5: "MODP1536",
    14: "MODP2048",
    15: "MODP3072",
    16: "MODP4096",
    17: "MODP6144",
    18: "MODP8192",
    19: "ECP256",
    20: "ECP384",
    21: "ECP521",
}


def parse_transform_attribute(data):
    """
    Parse IKEv2 transform attributes.

    AES key length:
        attribute type 14
        value = key length in bits
    """

    attributes = {}

    offset = 0

    while offset + 4 <= len(data):

        attr_type = struct.unpack(
            "!H",
            data[offset:offset + 2]
        )[0]

        attr_value = struct.unpack(
            "!H",
            data[offset + 2:offset + 4]
        )[0]

        offset += 4

        # Remove TV/TLV flag.
        attr_type_clean = attr_type & 0x7fff

        if attr_type_clean == 14:
            attributes["key_length"] = attr_value

    return attributes


def parse_ike_sa_payload(data):
    """
    Parse the body of an IKEv2 SA payload.

    The data passed here starts at the first Proposal structure.
    """

    result = {
        "encryption": None,
        "integrity": None,
        "prf": None,
        "dh_group": None,
        "key_length": None
    }

    offset = 0

    while offset + 8 <= len(data):

        # -------------------------
        # Proposal header
        # -------------------------

        next_proposal = data[offset]

        proposal_length = struct.unpack(
            "!H",
            data[offset + 2:offset + 4]
        )[0]

        if proposal_length < 8:
            break

        proposal_end = offset + proposal_length

        if proposal_end > len(data):
            break

        spi_size = data[offset + 6]
        num_transforms = data[offset + 7]

        transform_offset = offset + 8 + spi_size

        # -------------------------
        # Parse transforms
        # -------------------------

        for _ in range(num_transforms):

            if transform_offset + 8 > proposal_end:
                break

            transform_length = struct.unpack(
                "!H",
                data[
                    transform_offset + 2:
                    transform_offset + 4
                ]
            )[0]

            transform_type = data[transform_offset + 4]

            transform_id = struct.unpack(
                "!H",
                data[
                    transform_offset + 6:
                    transform_offset + 8
                ]
            )[0]

            if transform_length < 8:
                break

            transform_end = transform_offset + transform_length

            if transform_end > proposal_end:
                break

            transform_data = data[
                transform_offset + 8:
                transform_end
            ]

            # -------------------------
            # Encryption
            # -------------------------

            if transform_type == 1:

                result["encryption"] = ENCRYPTION_ALGORITHMS.get(
                    transform_id,
                    f"Unknown ({transform_id})"
                )

                attributes = parse_transform_attribute(
                    transform_data
                )

                if "key_length" in attributes:
                    result["key_length"] = attributes["key_length"]

            # -------------------------
            # PRF
            # -------------------------

            elif transform_type == 2:

                result["prf"] = PRF_ALGORITHMS.get(
                    transform_id,
                    f"Unknown ({transform_id})"
                )

            # -------------------------
            # Integrity
            # -------------------------

            elif transform_type == 3:

                result["integrity"] = INTEGRITY_ALGORITHMS.get(
                    transform_id,
                    f"Unknown ({transform_id})"
                )

            # -------------------------
            # Diffie-Hellman
            # -------------------------

            elif transform_type == 4:

                result["dh_group"] = DH_GROUPS.get(
                    transform_id,
                    f"Unknown ({transform_id})"
                )

            transform_offset = transform_end

        offset = proposal_end

        if next_proposal == 0:
            break

    return result


def get_udp_payload(packet):
    """
    Return raw UDP payload.

    For IKE over UDP 4500 (NAT-T), the first four bytes
    are a non-ESP marker:

        00 00 00 00

    We remove that marker before parsing the IKE header.
    """

    if UDP not in packet:
        return b""

    try:
        payload = bytes(packet[UDP].payload)
    except Exception:
        return b""

    if not payload:
        return b""

    # NAT-T non-ESP marker.
    if (
        (packet[UDP].sport == 4500 or packet[UDP].dport == 4500)
        and payload[:4] == b"\x00\x00\x00\x00"
    ):
        payload = payload[4:]

    return payload


def parse_raw_ike_header(data):
    """
    Parse the IKEv2 header directly from raw bytes.

    IKEv2 header is 28 bytes:

        0-7    Initiator SPI
        8-15   Responder SPI
        16     Next Payload
        17     Version
        18     Exchange Type
        19     Flags
        20-23  Message ID
        24-27  Length
    """

    if len(data) < 28:
        return None

    version = data[17]
    exchange = data[18]
    flags = data[19]
    next_payload = data[16]

    # IKEv2 version is normally 0x20.
    if (version >> 4) != 2:
        return None

    return {
        "version": "IKEv2",
        "exchange": exchange,
        "exchange_name": IKE_EXCHANGES.get(
            exchange,
            f"Unknown ({exchange})"
        ),
        "flags": flags,
        "is_response": bool(flags & 0x20),
        "next_payload": next_payload
    }


def extract_ike_sa_payload(data):
    """
    Walk the IKEv2 payload chain and return the body of
    the first SA payload found.

    SA payload type = 33.
    """

    header = parse_raw_ike_header(data)

    if header is None:
        return None

    next_payload = header["next_payload"]

    offset = 28

    while next_payload != 0:

        if offset + 4 > len(data):
            return None

        payload_next = data[offset]

        payload_length = struct.unpack(
            "!H",
            data[offset + 2:offset + 4]
        )[0]

        if payload_length < 4:
            return None

        payload_end = offset + payload_length

        if payload_end > len(data):
            return None

        # SA payload
        if next_payload == 33:

            return data[
                offset + 4:
                payload_end
            ]

        next_payload = payload_next
        offset = payload_end

    return None


def parse_raw_ike_packet(data):
    """
    Parse an IKEv2 packet directly from raw UDP bytes.

    Returns header information and, when present,
    cryptographic parameters from the SA payload.
    """

    header = parse_raw_ike_header(data)

    if header is None:
        return None

    result = {
        "version": header["version"],
        "exchange": header["exchange"],
        "exchange_name": header["exchange_name"],
        "is_response": header["is_response"],
        "crypto": None
    }

    # IKE_SA_INIT carries the initial SA proposal.
    if header["exchange"] == 34:

        try:

            sa_data = extract_ike_sa_payload(data)

            if sa_data:

                crypto = parse_ike_sa_payload(sa_data)

                result["crypto"] = crypto

        except Exception:
            pass

    return result


def analyze_pcap(filename):

    packets = rdpcap(filename)

    esp_packets = []
    ike_packets = []

    ike_version = None
    ike_exchanges = []

    source_ips = set()
    destination_ips = set()

    spis = set()
    sequences = []
    esp_sizes = []

    # We keep responder-selected crypto separately because
    # the IKE_SA_INIT response represents the negotiated choice.
    responder_crypto = None
    request_crypto = None

    # -------------------------
    # Packet processing
    # -------------------------

    for packet in packets:

        # -------------------------
        # IP addresses
        # -------------------------

        if IP in packet:

            source_ips.add(packet[IP].src)
            destination_ips.add(packet[IP].dst)

        # -------------------------
        # ESP
        # -------------------------

        if ESP in packet:

            esp_packets.append(packet)

            try:
                spis.add(packet[ESP].spi)
                sequences.append(packet[ESP].seq)
                esp_sizes.append(len(packet))
            except Exception:
                pass

        # -------------------------
        # IKE
        # -------------------------

        if UDP in packet:

            if (
                packet[UDP].sport in [500, 4500]
                or packet[UDP].dport in [500, 4500]
            ):

                raw_ike = get_udp_payload(packet)

                parsed_ike = parse_raw_ike_packet(raw_ike)

                # Only count packets that actually look like IKE.
                if parsed_ike is None:
                    continue

                ike_packets.append(packet)

                ike_version = parsed_ike["version"]

                ike_exchanges.append(
                    parsed_ike["exchange_name"]
                )

                # -------------------------
                # Extract crypto
                # -------------------------

                if (
                    parsed_ike["exchange"] == 34
                    and parsed_ike["crypto"] is not None
                ):

                    if parsed_ike["is_response"]:

                        responder_crypto = parsed_ike["crypto"]

                    elif request_crypto is None:

                        request_crypto = parsed_ike["crypto"]

    # -------------------------
    # Select crypto result
    # -------------------------

    ike_crypto = {
        "encryption": None,
        "key_length": None,
        "integrity": None,
        "prf": None,
        "dh_group": None
    }

    # Prefer responder's IKE_SA_INIT response.
    selected_crypto = (
        responder_crypto
        if responder_crypto is not None
        else request_crypto
    )

    if selected_crypto is not None:

        for key in ike_crypto:

            if selected_crypto.get(key) is not None:

                ike_crypto[key] = selected_crypto[key]

    # -------------------------
    # Traffic statistics
    # -------------------------

    if esp_sizes:

        average_esp_size = round(
            sum(esp_sizes) / len(esp_sizes),
            2
        )

        min_esp_size = min(esp_sizes)
        max_esp_size = max(esp_sizes)

    else:

        average_esp_size = 0
        min_esp_size = 0
        max_esp_size = 0

    # -------------------------
    # Protocol identification
    # -------------------------

    if esp_packets or ike_packets:

        protocol = "IPsec"

    else:

        protocol = "Unknown"

    # -------------------------
    # Result
    # -------------------------

    result = {

        "protocol": protocol,

        "ike": {
            "version": ike_version,
            "exchanges": list(set(ike_exchanges)),
            "packet_count": len(ike_packets)
        },

        "crypto": ike_crypto,

        "esp": {
            "packet_count": len(esp_packets),

            "unique_spis": len(spis),

            "spis": [
                hex(spi)
                for spi in spis
            ],

            "sequence_min": (
                min(sequences)
                if sequences
                else None
            ),

            "sequence_max": (
                max(sequences)
                if sequences
                else None
            ),

            "average_packet_size": average_esp_size,

            "min_packet_size": min_esp_size,

            "max_packet_size": max_esp_size
        },

        "traffic": {
            "total_packets": len(packets),

            "source_ips": list(source_ips),

            "destination_ips": list(destination_ips)
        }
    }

    return result


if __name__ == "__main__":

    filename = "data/ike_test3.pcap"

    result = analyze_pcap(filename)

    print("\nIPsec VPN Analyzer")
    print("==================")

    print(
        "Protocol:",
        result["protocol"]
    )

    print("\nIKE")
    print("---")

    print(
        "Version:",
        result["ike"]["version"]
    )

    print(
        "Packets:",
        result["ike"]["packet_count"]
    )

    print(
        "Exchanges:",
        ", ".join(result["ike"]["exchanges"])
    )

    print("\nCryptography")
    print("------------")

    print(
        "Encryption:",
        result["crypto"]["encryption"]
    )

    print(
        "Key Length:",
        result["crypto"]["key_length"],
        "bits"
        if result["crypto"]["key_length"]
        else ""
    )

    print(
        "Integrity:",
        result["crypto"]["integrity"]
    )

    print(
        "PRF:",
        result["crypto"]["prf"]
    )

    print(
        "DH Group:",
        result["crypto"]["dh_group"]
    )

    print("\nESP")
    print("---")

    print(
        "ESP packets:",
        result["esp"]["packet_count"]
    )

    print(
        "Unique SPIs:",
        result["esp"]["unique_spis"]
    )

    print(
        "SPI values:",
        result["esp"]["spis"]
    )

    print(
        "Sequence range:",
        result["esp"]["sequence_min"],
        "->",
        result["esp"]["sequence_max"]
    )

    print(
        "Average ESP size:",
        result["esp"]["average_packet_size"]
    )

    print(
        "Min ESP size:",
        result["esp"]["min_packet_size"]
    )

    print(
        "Max ESP size:",
        result["esp"]["max_packet_size"]
    )