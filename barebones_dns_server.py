import logging
import socket
import socketserver
from pprint import pformat

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

HEADER_QR_INT_TO_VAL = {
    0: "QUERY", 1: "RESPONSE",
}
HEADER_QR_VAL_TO_INT = {v: k for k, v in HEADER_QR_INT_TO_VAL.items()}

HEADER_OPCODE_INT_TO_VAL = {
    0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE",
}
HEADER_OPCODE_VAL_TO_INT = {v: k for k, v in HEADER_OPCODE_INT_TO_VAL.items()}

HEADER_RCODE_INT_TO_VAL = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
    6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}
HEADER_RCODE_VAL_TO_INT = {v: k for k, v in HEADER_RCODE_INT_TO_VAL.items()}

RR_TYPE_INT_TO_VAL = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 13: "HINFO", 15: "MX",
    16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC",
    33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6", 39: "DNAME", 41: "OPT",
    42: "APL", 43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC",
    48: "DNSKEY", 49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "HIP",
    55: "HIP", 59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY",  62: "CSYNC", 63: "ZONEMD",
    64: "SVCB", 65: "HTTPS", 99: "SPF", 108: "EUI48", 109: "EUI64", 249: "TKEY",
    250: "TSIG", 251: "IXFR", 252: "AXFR", 255: "*", 256: "URI", 257: "CAA",
    32768: "TA", 32769: "DLV",
}
RR_TYPE_VAL_TO_INT = {v: k for k, v in RR_TYPE_INT_TO_VAL.items()}

RR_CLASS_INT_TO_VAL = {
    1: "IN", 2: "CS", 3: "CH", 4: "HS", 254: "NONE", 255: "*",
}
RR_CLASS_VAL_TO_INT = {v: k for k, v in RR_CLASS_INT_TO_VAL.items()}


def bitmap_split(bitmap, d_in):
    """
    Split bytes into bit subfields (e.g. split packet into flags/subfields)
    """
    d_int = int.from_bytes(d_in, byteorder="big", signed=False)
    results = []
    cursor = len(d_in) * 8
    assert sum(bitmap) == cursor, f"bitmap len ({sum(bitmap)} bits) != data len ({cursor} bits)"
    for subfield_len in bitmap:
        cursor = cursor - subfield_len
        results.append((d_int >> cursor) & ((2 ** subfield_len) - 1))
    return results


def read_name(overall_bytes, overall_offset, max_offset=None, end_offset=None):
    """
    Read a domain name or character string that is split into length-designated labels
    (also handles DNS compression pointers).
    """
    # for compression pointers, we never want to read past the original pointer location
    # (to prevent infinite loops)
    if max_offset is not None and overall_offset >= max_offset:
        raise ValueError(f"Compression pointer ({overall_offset}) >= current position ({max_offset})")

    # iterate through the bytes, parsing the label
    labels = []
    cur_offset = overall_offset
    while True:

        # for character strings, they don't end in a zero length label, so the function is
        # passed an ending offset to let us know when we're done 
        if end_offset is not None and cur_offset >= end_offset:
            return labels, cur_offset

        # compression pointers have the leading two bits as 1s and are 2 bytes long
        compression_flags, _ = bitmap_split([2, 6], overall_bytes[cur_offset:(cur_offset+1)])
        if compression_flags == 3:
            # read the remaining 14 bits for the pointer offset
            _, compression_offset = bitmap_split([2, 14], overall_bytes[cur_offset:(cur_offset+2)])
            cur_offset += 2
            # recursively read from where the pointer pointed until the end of that name
            compressed_labels, _ = read_name(overall_bytes, compression_offset, max_offset=overall_offset)
            labels.extend(compressed_labels)
            # pointers are always the end of the name list, so go ahead and return
            return labels, cur_offset

        # not a compression pointer, so just read the label as a normal bytestring
        else:
            # the first byte of the label is the label's length
            label_len = int.from_bytes(overall_bytes[cur_offset:(cur_offset+1)], "big")
            cur_offset += 1
            # zero-length bytestrings indicate the end of the name list
            if label_len == 0:
                return labels, cur_offset
            # read the label's bytestring and add it to the results
            label_val = overall_bytes[cur_offset:(cur_offset+label_len)]
            labels.append(label_val)
            # update the current offset to the end of this chunk
            cur_offset += label_len


def parse_RR(buf, buf_offset, is_question=False):
    """
    Parse a question or resource record (RR) entry into a dict. 
    """
    RR = {
        "name": None,       # e.g. b"www.example.com"
        "type_int": None,   # e.g. 5
        "type": None,       # e.g. "CNAME"
        "class_int": None,  # e.g. 1
        "class": None,      # e.g. "IN"
        #"ttl": None,       # e.g. 600 (not included in questions)
        #"rdlength": None,  # e.g. 120 (not included in questions)
        #"rdata": None,     # format depends on the type (not included in questions)
    }

    # read the variable length name
    name_parts, buf_offset = read_name(buf, buf_offset)
    RR['name'] = b".".join(name_parts)

    # resource record type
    RR['type_int'] = int.from_bytes(buf[buf_offset:(buf_offset+2)], "big")
    RR['type'] = RR_TYPE_INT_TO_VAL.get(RR['type_int'], None)
    buf_offset += 2

    # resource record class
    RR['class_int'] = int.from_bytes(buf[buf_offset:(buf_offset+2)], "big")
    RR['class'] = RR_CLASS_INT_TO_VAL.get(RR['class_int'], None)
    buf_offset += 2

    # questions are just truncated resource records (no TTL, RDLENGTH, or RDATA)
    if is_question:
        return RR, buf_offset

    # TTL
    RR['ttl'] = int.from_bytes(buf[buf_offset:(buf_offset+4)], "big")
    buf_offset += 4

    # RDATA length (i.e. RDLENGTH)
    RR['rdlength'] = int.from_bytes(buf[buf_offset:(buf_offset+2)], "big")
    buf_offset += 2

    #################################
    ## RDATA type-specific parsing ##
    #################################
    orig_offset = buf_offset

    # CNAME, PTR, NS (domain-name values)
    # e.g. "rdata": b"www2.example.com",
    if RR['type'] in ["CNAME", "PTR", "NS"]:
        doamin_parts, _ = read_name(buf, buf_offset)
        RR['rdata'] = b".".join(doamin_parts)

    # A, AAAA (ip addresses)
    # e.g. "rdata": "192.168.1.1" or "4321:0:1:2:3:4:567:89ab",
    elif RR['type'] == "A":
        RR['rdata'] = socket.inet_ntop(socket.AF_INET, buf[buf_offset:(buf_offset+4)])
    elif RR['type'] == "AAAA":
        RR['rdata'] = socket.inet_ntop(socket.AF_INET6, buf[buf_offset:(buf_offset+16)])

    # TXT
    # e.g. "rdata": b"some text value here",
    elif RR['type'] == "TXT":
        txt_end = buf_offset + RR['rdlength']
        string_parts, _ = read_name(buf, buf_offset, end_offset=txt_end)
        RR['rdata'] = b"".join(string_parts)

    # MX
    # e.g. "rdata": {"preference": 10, "exchange": b"mx1.google.com"},
    elif RR['type'] == "MX":
        RR['rdata'] = {
            "preference": int.from_bytes(buf[buf_offset:(buf_offset+2)], "big"),
            "exchange": None,
        }
        buf_offset += 2
        exchange_parts, _ = read_name(buf, buf_offset)
        RR['rdata']['exchange'] = b".".join(exchange_parts)

    # SOA values
    # e.g. "rdata": {"mname": ...},
    elif RR['type'] == "SOA":
        RR['rdata'] = {
            "mname": None,      # e.g. b"aaa1.bbb.com"
            "rname": None,      # e.g. b"aaa2.bbb.com"
            "serial": None,     # e.g. 123123121231
            "refresh": None,    # e.g. 60
            "retry": None,      # e.g. 3600
            "expire": None,     # e.g. 3600
            "minimum": None,    # e.g. 60
        }
        mname_parts, buf_offset = read_name(buf, buf_offset)
        RR['rdata']['mname'] = b".".join(mname_parts)

        rname_parts, buf_offset = read_name(buf, buf_offset)
        RR['rdata']['rname'] = b".".join(rname_parts)

        RR['rdata']['serial' ] = int.from_bytes(buf[(buf_offset+0):(buf_offset+4)], "big")
        RR['rdata']['refresh'] = int.from_bytes(buf[(buf_offset+4):(buf_offset+8)], "big")
        RR['rdata']['retry'  ] = int.from_bytes(buf[(buf_offset+8):(buf_offset+12)], "big")
        RR['rdata']['expire' ] = int.from_bytes(buf[(buf_offset+12):(buf_offset+16)], "big")
        RR['rdata']['minimum'] = int.from_bytes(buf[(buf_offset+16):(buf_offset+20)], "big")

    # all other types are default to RDATA as just raw bytes
    # e.g. "rdata": b"\x01\xff...",
    else:
        RR['rdata'] = buf[buf_offset:(buf_offset+RR['rdlength'])]

    # no matter where we ended up in the parsing, set the ending offset as the RDATA length
    buf_offset = orig_offset + RR['rdlength']

    return RR, buf_offset


def rr_to_bytes(rr, is_question=False):
    """
    Transform a resource record (RR) or question to bytes.
    """
    rr_bytes = b""

    # convert name into series of labels (don't do any compression)
    labels = rr['name'].split(b".")
    for label in labels:
        rr_bytes += len(label).to_bytes(1, byteorder="big") + label
    rr_bytes += b"\x00"

    # convert type value to bytes
    rr_bytes += RR_TYPE_VAL_TO_INT.get(rr['type'], rr.get("type_int", 0)).to_bytes(2, byteorder="big")

    # convert class value to bytes
    rr_bytes += RR_CLASS_VAL_TO_INT.get(rr['class'], rr.get("class_int", 0)).to_bytes(2, byteorder="big")

    # questions are done after name, type, and class
    if is_question:
        return rr_bytes

    # TTL
    rr_bytes += rr['ttl'].to_bytes(4, byteorder="big")

    #################################
    ## RDATA type-specific parsing ##
    #################################
    rdata_bytes = b""

    # CNAME, PTR, NS (domain-name values)
    if rr['type'] in ["CNAME", "PTR", "NS"]:
        for domain_part in rr['rdata'].split(b"."):
            rdata_bytes += len(domain_part).to_bytes(1, byteorder="big") + domain_part
        rdata_bytes += b"\x00"

    # A, AAAA (ip addresses)
    elif rr['type'] == "A":
        rdata_bytes += socket.inet_pton(socket.AF_INET, rr['rdata'])
    elif rr['type'] == "AAAA":
        rdata_bytes += socket.inet_pton(socket.AF_INET6, rr['rdata'])

    # TXT
    elif rr['type'] == "TXT":
        txt_offset = 0
        while txt_offset < len(rr['rdata']):
            txt_offset_end = txt_offset + 255
            txt_chunk = rr['rdata'][txt_offset:txt_offset_end]
            rdata_bytes += len(txt_chunk).to_bytes(1, byteorder="big") + txt_chunk
            txt_offset = txt_offset_end

    # MX
    elif rr['type'] == "MX":
        # MX preference
        rdata_bytes += rr['rdata']['preference'].to_bytes(2, byteorder="big")
        # MX exchange domain
        for exchange_part in rr['rdata']['exchange'].split(b"."):
            rdata_bytes += len(exchange_part).to_bytes(1, byteorder="big") + exchange_part
        rdata_bytes += b"\x00"

    # SOA
    elif rr['type'] == "SOA":
        # SOA mname
        for mname_part in rr['rdata']['mname'].split(b"."):
            rdata_bytes += len(mname_part).to_bytes(1, byteorder="big") + mname_part
        rdata_bytes += b"\x00"
        # SOA rname
        for rname_part in rr['rdata']['rname'].split(b"."):
            rdata_bytes += len(rname_part).to_bytes(1, byteorder="big") + rname_part
        rdata_bytes += b"\x00"
        # SOA serial
        rdata_bytes += rr['rdata']['serial'].to_bytes(4, byteorder="big")
        # SOA refresh
        rdata_bytes += rr['rdata']['refresh'].to_bytes(4, byteorder="big")
        # SOA retry
        rdata_bytes += rr['rdata']['retry'].to_bytes(4, byteorder="big")
        # SOA expire
        rdata_bytes += rr['rdata']['expire'].to_bytes(4, byteorder="big")
        # SOA minimum
        rdata_bytes += rr['rdata']['minimum'].to_bytes(4, byteorder="big")

    # all other types are default to RDATA as just raw bytes
    else:
        rdata_bytes += rr['rdata']

    # calculate final RDLENGTH and append RDATA to final result
    rr_bytes += len(rdata_bytes).to_bytes(2, byteorder="big") + rdata_bytes

    return rr_bytes


def parse_dns_packet(raw):
    """ Parse a raw DNS request packet and return a dict with the various sections """
    # parse header
    flags = bitmap_split([1, 4, 1, 1, 1, 1, 3, 4], raw[2:4])
    parsed = {
        "header": {
            "id": int.from_bytes(raw[0:2], "big"),
            "qr_int": flags[0],
            "qr": HEADER_QR_INT_TO_VAL.get(flags[0], None),
            "opcode_int": flags[1],
            "opcode": HEADER_OPCODE_INT_TO_VAL.get(flags[1], None),
            "aa": flags[2],
            "tc": flags[3],
            "rd": flags[4],
            "ra": flags[5],
            "z": flags[6],
            "rcode_int": flags[7],
            "rcode": HEADER_RCODE_INT_TO_VAL.get(flags[7], None),
            "num_questions": int.from_bytes(raw[4:6], "big"),
            "num_answers": int.from_bytes(raw[6:8], "big"),
            "num_authority_records": int.from_bytes(raw[8:10], "big"),
            "num_additional_records": int.from_bytes(raw[10:12], "big"),
        },
        "questions": [],
        "answers": [],
        "authority_records": [],
        "additional_records": [],
    }
    raw_offset = 12

    # parse the lists of question and resource records
    for rr_category in [
        "questions",
        "answers",
        "authority_records",
        "additional_records",
    ]:
        for rr_i in range(parsed['header']["num_" + rr_category]):
            rr, raw_offset = parse_RR(raw, raw_offset, is_question=(rr_category == "questions"))
            parsed[rr_category].append(rr)

    return parsed


def dns_packet_to_bytes(parsed):
    """
    Transform a parsed DNS packet into bytes for delivery.
    """
    # convert flag values to ints
    qr_int = HEADER_QR_VAL_TO_INT[parsed['header']['qr']]
    opcode_int = HEADER_OPCODE_VAL_TO_INT[parsed['header']['opcode']]
    rcode_int = HEADER_RCODE_VAL_TO_INT[parsed['header']['rcode']]

    # compile header flags into bytes
    flags_int = 0
    flags_int |= (qr_int                 << (16 - 1))
    flags_int |= (opcode_int             << (16 - 1 - 4))
    flags_int |= (parsed['header']['aa'] << (16 - 1 - 4 - 1))
    flags_int |= (parsed['header']['tc'] << (16 - 1 - 4 - 1 - 1))
    flags_int |= (parsed['header']['rd'] << (16 - 1 - 4 - 1 - 1 - 1))
    flags_int |= (parsed['header']['ra'] << (16 - 1 - 4 - 1 - 1 - 1 - 1))
    flags_int |= (parsed['header']['z']  << (16 - 1 - 4 - 1 - 1 - 1 - 1 - 3))
    flags_int |= (rcode_int              << (16 - 1 - 4 - 1 - 1 - 1 - 1 - 3 - 4))
    flags_bytes = flags_int.to_bytes(2, byteorder="big")

    # make header bytes
    final_bytes = b"".join([
        parsed['header']['id'].to_bytes(2, byteorder="big"),
        flags_bytes,
        parsed['header']['num_questions'].to_bytes(2, byteorder="big"),
        parsed['header']['num_answers'].to_bytes(2, byteorder="big"),
        parsed['header']['num_authority_records'].to_bytes(2, byteorder="big"),
        parsed['header']['num_additional_records'].to_bytes(2, byteorder="big"),
    ])

    # convert resource records to bytes
    for rr_category in [
        "questions",
        "answers",
        "authority_records",
        "additional_records",
    ]:
        for RR in parsed[rr_category]:
            rr_bytes = rr_to_bytes(RR, is_question=(rr_category == "questions"))
            final_bytes += rr_bytes

    return final_bytes


def handle_question(question, config):
    """
    Process a question and build answers to the query.
    """
    answers = []
    is_authoritative = False

    # only answer domains for which the server is the authority (edge dns server)
    for a_domain in config['authoritative_domains']:
        if question['name'].endswith(a_domain):

            # mark as authoritative response, even if we don't have a matching domain
            is_authoritative = True

            # scan domains in config for a match
            for domain_re, domain_logic in config['domains']:
                if domain_re.match(question['name']):

                    # allow arbitrary functions for dynamic results
                    if callable(domain_logic):
                        domain_logic = domain_logic(question)

                    # allow ALL query type
                    q_types = [question['type']]
                    if question['type'] == "*":
                        q_types = domain_logic.keys()

                    # Include CNAME in A and AAAA request responses
                    if question['type'] in ["A", "AAAA"]:
                        q_types.append("CNAME")

                    # generate answer if there's a config for that query type (A, TXT, etc.)
                    for q_type in q_types:
                        for rr_rdata, rr_ttl in domain_logic.get(q_type, []):
                            answers.append({
                                "name": question['name'],
                                "type": q_type,
                                "class": "IN",
                                "ttl": rr_ttl,
                                "rdata": rr_rdata,
                            })

                    # stop looping since we found a match on the domain
                    break

            # stop looping since we found a match on the authoritative domain
            break 

    return answers, is_authoritative


def handle_dns_packet(packet_bytes, config, logger=LOGGER):
    """
    Process a DNS query into answers (or empty answer).
    """
    # parse the incoming dns query packet
    logger.debug("Incoming DNS packet bytes: {}".format(packet_bytes))
    packet_dict = parse_dns_packet(packet_bytes)
    logger.debug("Parsed incoming DNS packet: {}".format(pformat(packet_dict)))

    # default response payload is an error
    response_packet = {
        "header": {
            "id": packet_dict['header']['id'],
            "qr": "RESPONSE",
            "opcode": "QUERY",
            "aa": 0,  # authoritative answer (1 if query has domain that this server controls)
            "tc": 0,  # no truncation
            "rd": 0,  # no recursion desired
            "ra": 0,  # no recursion available
            "z": 0,   # always zero
            "rcode": "SERVFAIL", # "NOERROR" if has answer; "NXDOMAIN" if no domain matches
            "num_questions": 0,
            "num_answers": 0,
            "num_authority_records": 0,
            "num_additional_records": 0,
        },
        "questions": [],
        "answers": [],
        "authority_records": [],
        "additional_records": [],
    }

    # only try to answer the first question
    is_authoritative = False
    if packet_dict['questions']:
        response_packet['questions'] = [packet_dict['questions'][0]]
        response_packet['answers'], is_authoritative = handle_question(packet_dict['questions'][0], config)

    # update response header metadata based on answer results
    response_packet['header']['aa'] = 1 if is_authoritative else 0
    response_packet['header']['rcode'] = "NOERROR" if response_packet['answers'] else "NXDOMAIN"
    response_packet['header']['num_questions'] = len(response_packet['questions'])
    response_packet['header']['num_answers'] = len(response_packet['answers'])
    logger.debug("Response DNS packet dict: {}".format(pformat(response_packet)))

    # compile response into bytes
    response_bytes = dns_packet_to_bytes(response_packet)
    logger.debug("Response DNS packet bytes: {}".format(response_bytes))

    return response_bytes


class BarebonesDNSUDPHandler(socketserver.BaseRequestHandler):
    """ Basic UDP request handler class """
    DNS_CONFIG = None
    DNS_LOGGER = None
    def handle(self):
        incoming_packet, socket = self.request
        response_packet = handle_dns_packet(incoming_packet, self.DNS_CONFIG, logger=(self.DNS_LOGGER or LOGGER))
        socket.sendto(response_packet, self.client_address)


# start server when module is run directly
if __name__ == "__main__":
    import argparse, importlib
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default="127.0.0.1")
    parser.add_argument('--port', default=5353, type=int)
    parser.add_argument('--config', default="example_config")
    parser.add_argument("--debug", action="store_const", const=logging.DEBUG)
    args = parser.parse_args()

    LOGGER.setLevel(args.debug or LOGGER.level)
    LOGGER.info("Running DNS server on {}:{}...".format(args.host, args.port))

    BarebonesDNSUDPHandler.DNS_CONFIG = importlib.import_module(args.config).DNS_CONFIG
    BarebonesDNSUDPHandler.DNS_LOGGER = LOGGER

    socketserver.ForkingUDPServer.allow_reuse_address = True
    with socketserver.ForkingUDPServer((args.host, args.port), BarebonesDNSUDPHandler) as server:
        server.serve_forever()

