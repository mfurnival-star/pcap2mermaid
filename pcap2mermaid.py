#!/usr/bin/env python3
"""
pcap2mermaid: Convert SIP packets in a pcap file to a Mermaid sequence diagram.

Usage:
    python3 pcap2mermaid.py input.pcap [output.md] [options]

Dependencies:
    pip install scapy
"""
import sys
import os
import re
import argparse
import logging
import csv
from scapy.all import PcapReader, UDP, TCP, IP, IPv6, Raw

DEFAULT_SIP_PORT = 5060
LARGE_PCAP_MB = 500

def check_input_file(infile):
    if not os.path.isfile(infile):
        logging.error(f"Input file '{infile}' does not exist or is not a file.")
        sys.exit(1)
    if not os.access(infile, os.R_OK):
        logging.error(f"Input file '{infile}' is not readable.")
        sys.exit(1)
    size_mb = os.path.getsize(infile) / (1024 * 1024)
    if size_mb > LARGE_PCAP_MB:
        logging.warning(f"Input file '{infile}' is very large ({size_mb:.1f} MB). Consider filtering or splitting.")

def check_output_file(outfile):
    try:
        with open(outfile, "w") as f:
            pass
    except Exception as e:
        logging.error(f"Cannot write to output file '{outfile}': {e}")
        sys.exit(1)

def parse_mapping(mapping_str):
    host2name = {}
    if mapping_str:
        for h in mapping_str.split(","):
            parts = h.split("=")
            if len(parts) != 2:
                logging.error("Invalid mapping: '%s'", h)
                sys.exit("Mapping must be comma-separated '<ip>:<port>=<name>'")
            host2name[parts[0]] = parts[1]
    return host2name

def parse_participant_csv(csv_file):
    host2name = {}
    try:
        with open(csv_file, newline='') as csvf:
            for row in csv.reader(csvf):
                if not row or len(row) < 2:
                    continue
                host2name[row[0]] = row[1]
    except Exception as e:
        logging.error(f"Error reading participant names CSV '{csv_file}': {e}")
        sys.exit(1)
    return host2name

def parse_sip(data):
    try:
        text = data.decode(errors="ignore")
    except Exception:
        return None

    text = text.lstrip()
    req_match = re.match(r"^([A-Z]+)\s+sip:([^ ]+)\s+SIP/2.0", text)
    if req_match:
        # Only keep part before ';' in target
        target = req_match.group(2).split(';', 1)[0]
        return {
            'is_request': True,
            'method': req_match.group(1),
            'target': target,
            'raw_line': text.splitlines()[0]
        }
    resp_match = re.match(r"^SIP/2.0\s+(\d{3})\s+(.+)", text)
    if resp_match:
        return {
            'is_request': False,
            'code': int(resp_match.group(1)),
            'reason': resp_match.group(2).strip(),
            'raw_line': text.splitlines()[0]
        }
    return None

def hostport(ip, port):
    if ':' in ip and not ip.startswith('['):
        return f"{ip}:{port}"
    else:
        return f"{ip}:{port}"

def process_pcap(
    infile, 
    filter_port, 
    host2name, 
    filter_unmapped, 
    skip_provisional=True,
    method_filter=None,
    status_filter=None,
    progress_every=10000,
    logger=None,
):
    sip_packets = []
    pkt_count = 0
    all_participants = set()
    dropped = 0
    dropped_reasons = {}
    try:
        with PcapReader(infile) as pcap:
            for pkt in pcap:
                pkt_count += 1
                if pkt_count % progress_every == 0:
                    logger and logger.info(f"Processed {pkt_count} packets...")
                # IP Layer
                if IP in pkt:
                    l3 = pkt[IP]
                    src_ip, dst_ip = l3.src, l3.dst
                elif IPv6 in pkt:
                    l3 = pkt[IPv6]
                    src_ip, dst_ip = l3.src, l3.dst
                else:
                    dropped += 1
                    dropped_reasons['no_ip'] = dropped_reasons.get('no_ip', 0) + 1
                    continue

                # L4 Layer
                if UDP in pkt:
                    l4 = pkt[UDP]
                elif TCP in pkt:
                    l4 = pkt[TCP]
                else:
                    dropped += 1
                    dropped_reasons['no_udp_tcp'] = dropped_reasons.get('no_udp_tcp', 0) + 1
                    continue

                src = hostport(src_ip, l4.sport)
                dst = hostport(dst_ip, l4.dport)
                all_participants.add(src)
                all_participants.add(dst)

                # Only SIP port in either direction
                if l4.dport != filter_port and l4.sport != filter_port:
                    dropped += 1
                    dropped_reasons['not_sip_port'] = dropped_reasons.get('not_sip_port', 0) + 1
                    continue

                # Only if payload
                if Raw not in l4:
                    dropped += 1
                    dropped_reasons['no_raw'] = dropped_reasons.get('no_raw', 0) + 1
                    continue

                sip_info = parse_sip(l4[Raw].load)
                if not sip_info:
                    dropped += 1
                    dropped_reasons['not_sip'] = dropped_reasons.get('not_sip', 0) + 1
                    continue

                if not sip_info['is_request']:
                    if skip_provisional and sip_info['code'] < 180:
                        dropped += 1
                        dropped_reasons['provisional'] = dropped_reasons.get('provisional', 0) + 1
                        continue

                # Filter by SIP method/status if requested
                if method_filter and sip_info.get('is_request'):
                    if sip_info.get('method', '').upper() not in method_filter:
                        dropped += 1
                        dropped_reasons['method_filter'] = dropped_reasons.get('method_filter', 0) + 1
                        continue
                if status_filter and not sip_info.get('is_request'):
                    if str(sip_info.get('code')) not in status_filter:
                        dropped += 1
                        dropped_reasons['status_filter'] = dropped_reasons.get('status_filter', 0) + 1
                        continue

                sip_packets.append({
                    'req': sip_info['is_request'],
                    'text': (
                        f"{sip_info['method']} {sip_info['target']}"
                        if sip_info['is_request']
                        else f"{sip_info['code']} ({sip_info['reason']})"
                    ),
                    'src': src,
                    'dst': dst,
                    'time': pkt.time
                })
    except MemoryError:
        logging.error("Out of memory reading large pcap file, try splitting it.")
        sys.exit(1)
    except Exception as e:
        logging.error("Error reading pcap: %s", e)
        sys.exit(1)

    logger and logger.info(f"Parsed {pkt_count} packets, found {len(sip_packets)} SIP messages, dropped {dropped}")
    return sip_packets, all_participants, pkt_count, dropped, dropped_reasons

def assign_participant_short_names(participants):
    sorted_participants = sorted(participants)
    # Use A, B, C, ... AA, AB, ...
    names = []
    for i in range(len(sorted_participants)):
        name = ''
        x = i
        while True:
            name = chr(ord('A') + (x % 26)) + name
            x = x // 26 - 1
            if x < 0:
                break
        names.append(name)
    return {host: short for host, short in zip(sorted_participants, names)}

def output_summary_table(outfh, participant_map, short_map):
    outfh.write("\n%% Participant Mapping Table\n")
    outfh.write("| Short Name | Host:Port |\n|-----------|-----------|\n")
    for host in sorted(participant_map.keys(), key=lambda k: short_map[k]):
        outfh.write(f"| {short_map[host]} | {host} |\n")

def main():
    parser = argparse.ArgumentParser(description="Convert SIP pcap to Mermaid sequence diagram.")
    parser.add_argument("infile", help="Input pcap file")
    parser.add_argument("outfile", nargs='?', help="Output Mermaid markdown file (omit to print to screen)")
    parser.add_argument("--mapping", help="CSV: <ip>:<port>=<name>,...", default=None)
    parser.add_argument("--participant-names", help="CSV file: <ip>:<port>,name", default=None)
    parser.add_argument("--port", help="SIP port (default 5060)", type=int, default=DEFAULT_SIP_PORT)
    parser.add_argument("--no-skip-provisional", help="Include <180 provisional SIP responses", action="store_true")
    parser.add_argument("--show-bottom-actors", help="Show actor boxes at the bottom (mirrorActors: true)", action="store_true")
    parser.add_argument("--verbose", help="Show debug and info log messages", action="store_true")
    parser.add_argument("--no-add-participants", help="Do not add participant lines to diagram", action="store_true")
    parser.add_argument("--autonumber", help="Enable Mermaid autonumbering", action="store_true")
    parser.add_argument("--filter-method", help="Comma-separated list of SIP methods (e.g., INVITE,BYE)", default=None)
    parser.add_argument("--filter-status", help="Comma-separated list of SIP status codes (e.g., 200,486)", default=None)
    parser.add_argument("--add-time", help="Annotate each message with packet timestamp", action="store_true")
    parser.add_argument("--summary-table", help="Add a summary table of participant names to output", action="store_true")
    parser.add_argument("--logfile", help="Save log messages to a file", default=None)
    parser.add_argument("--all-participants", help="Declare all possible participants seen, even if not shown in diagram", action="store_true")
    args = parser.parse_args()

    # Logging: quiet (ERROR) is default, unless verbose given
    if args.verbose:
        log_level = logging.INFO
    else:
        log_level = logging.ERROR

    if args.logfile:
        logging.basicConfig(filename=args.logfile, level=log_level, format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    logger = logging.getLogger("pcap2mermaid")

    check_input_file(args.infile)
    if args.outfile:
        check_output_file(args.outfile)

    host2name = parse_mapping(args.mapping)
    filter_unmapped = bool(args.mapping)

    if args.participant_names:
        host2name = parse_participant_csv(args.participant_names)
        filter_unmapped = bool(host2name)

    method_filter = [m.strip().upper() for m in args.filter_method.split(",")] if args.filter_method else None
    status_filter = [s.strip() for s in args.filter_status.split(",")] if args.filter_status else None

    sip_packets, all_participants, pkt_count, dropped, dropped_reasons = process_pcap(
        args.infile,
        args.port,
        host2name,
        filter_unmapped,
        skip_provisional=not args.no_skip_provisional,
        method_filter=method_filter,
        status_filter=status_filter,
        logger=logger
    )

    seq_count = 0

    # By default, add participants unless --no-add-participants is set
    add_participants = not args.no_add_participants

    # Assign short names if add_participants is specified
    if add_participants:
        if host2name:
            participant_map = {p: host2name[p] for p in all_participants if p in host2name}
        else:
            participant_map = {p: p for p in all_participants}
        short_map = assign_participant_short_names(participant_map.keys())
    else:
        participant_map = host2name if filter_unmapped else {}
        short_map = {p: p for p in all_participants}

    # Build set of used participants (those appearing in at least one SIP message in diagram)
    used_participants = set()
    for pkt in sip_packets:
        a, b = pkt['src'], pkt['dst']
        if filter_unmapped and (a not in participant_map or b not in participant_map):
            continue
        used_participants.add(a)
        used_participants.add(b)

    # By default, declare only used participants. If --all-participants is set, declare all.
    if add_participants:
        if args.all_participants:
            participants_to_write = participant_map.keys()
        else:
            participants_to_write = [h for h in participant_map.keys() if h in used_participants]

    # Decide output destination
    outfh = open(args.outfile, "w") if args.outfile else sys.stdout

    diagram_lines = []

    try:
        # Mermaid init config for mirrorActors: false (default), true if --show-bottom-actors
        mirror_val = "true" if args.show_bottom_actors else "false"
        diagram_lines.append(f'%%{{init: {{ "sequence": {{ "mirrorActors": {mirror_val} }} }} }}%%')
        diagram_lines.append("sequenceDiagram")
        if args.autonumber:
            diagram_lines.append("    autonumber")
        if add_participants:
            for host in sorted(participants_to_write, key=lambda k: short_map[k]):
                diagram_lines.append(f"    participant {short_map[host]} as {host}")
        for pkt in sip_packets:
            a, b = pkt['src'], pkt['dst']
            if filter_unmapped and (a not in participant_map or b not in participant_map):
                continue
            a_out = short_map[a] if add_participants else a
            b_out = short_map[b] if add_participants else b
            arrow = "->>" if pkt['req'] else "-->>"
            msg = pkt['text'].strip()
            # Remove all internal newlines and carriage returns and collapse whitespace
            msg = re.sub(r'\s+', ' ', msg).strip()
            if args.add_time:
                msg = f"[{pkt['time']:.3f}] {msg}"
            diagram_lines.append(f"    {a_out}{arrow}{b_out}: {msg}")
            seq_count += 1

        if args.summary_table and add_participants:
            # Build summary table lines
            diagram_lines.append("\n%% Participant Mapping Table")
            diagram_lines.append("| Short Name | Host:Port |\n|-----------|-----------|")
            for host in sorted(participant_map.keys(), key=lambda k: short_map[k]):
                diagram_lines.append(f"| {short_map[host]} | {host} |")

        # Write to file or stdout
        for line in diagram_lines:
            outfh.write(line + "\n")
    finally:
        if args.outfile:
            outfh.close()

    logger.info(f"Done, {seq_count} SIP packets written to sequence diagram ({'stdout' if not args.outfile else args.outfile})")
    logger.info(f"Processed {pkt_count} packets, dropped {dropped} packets for these reasons: {dropped_reasons}")

    if filter_unmapped:
        all_mapped = set(participant_map.keys())
        seen = all_participants
        unused = all_mapped - seen
        if unused:
            logger.warning(f"The following mappings in --mapping/CSV were never seen in the pcap: {unused}")
        unseen = seen - all_mapped
        if unseen:
            logger.warning(f"The following participants were seen in pcap but not mapped: {unseen}")

if __name__ == "__main__":
    main()
