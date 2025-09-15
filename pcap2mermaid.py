#!/usr/bin/env python3
"""
pcap2mermaid: Convert SIP packets in a pcap file to a Mermaid sequence diagram.

Usage:
    python3 pcap2mermaid.py input.pcap output.md [options]

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

def check_input_output_files(infile, outfile):
    if not os.path.isfile(infile):
        logging.error(f"Input file '{infile}' does not exist or is not a file.")
        sys.exit(1)
    if not os.access(infile, os.R_OK):
        logging.error(f"Input file '{infile}' is not readable.")
        sys.exit(1)
    try:
        with open(outfile, "w") as f:
            pass
    except Exception as e:
        logging.error(f"Cannot write to output file '{outfile}': {e}")
        sys.exit(1)
    # Large file warning
    size_mb = os.path.getsize(infile) / (1024 * 1024)
    if size_mb > LARGE_PCAP_MB:
        logging.warning(f"Input file '{infile}' is very large ({size_mb:.1f} MB). Consider filtering or splitting.")

def parse_mapping(mapping_str):
    """Parse the host mapping string."""
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
    """Parse custom participant name CSV (host:port,name)."""
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
    """
    Parse SIP message. Return dict with is_request, method, code, and raw_line.
    Returns None if not SIP.
    """
    try:
        text = data.decode(errors="ignore")
    except Exception:
        return None

    text = text.lstrip()
    req_match = re.match(r"^([A-Z]+)\s+sip:([^ ]+)\s+SIP/2.0", text)
    if req_match:
        return {
            'is_request': True,
            'method': req_match.group(1),
            'target': req_match.group(2),
            'raw_line': text.splitlines()[0]
        }
    resp_match = re.match(r"^SIP/2.0\s+(\d{3})\s+(.+)", text)
    if resp_match:
        return {
            'is_request': False,
            'code': int(resp_match.group(1)),
            'reason': resp_match.group(2),
            'raw_line': text.splitlines()[0]
        }
    return None

def hostport(ip, port):
    """Format host:port, handle IPv6."""
    if ':' in ip and not ip.startswith('['):
        return f"[{ip}]:{port}"
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
    """Process packets and return list of SIP packet dicts."""
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

def assign_participant_names(participants):
    """Assigns default participant names (P1, P2, ...) to each unique participant."""
    sorted_participants = sorted(participants)
    name_map = {}
    for idx, p in enumerate(sorted_participants, 1):
        name_map[p] = f"P{idx}"
    return name_map

def output_summary_table(outfile, participant_map):
    """Optionally output a summary mapping table at the top of the Mermaid/Markdown output."""
    with open(outfile, "a") as outfh:
        outfh.write("\n%% Participant Mapping Table\n")
        outfh.write("| Default Name | Host:Port |\n|-------------|-----------|\n")
        for host, name in participant_map.items():
            outfh.write(f"| {name} | {host} |\n")

def main():
    parser = argparse.ArgumentParser(description="Convert SIP pcap to Mermaid sequence diagram.")
    parser.add_argument("infile", help="Input pcap file")
    parser.add_argument("outfile", help="Output Mermaid markdown file")
    parser.add_argument("--mapping", help="CSV: <ip>:<port>=<name>,...", default=None)
    parser.add_argument("--participant-names", help="CSV file: <ip>:<port>,name", default=None)
    parser.add_argument("--port", help="SIP port (default 5060)", type=int, default=DEFAULT_SIP_PORT)
    parser.add_argument("--no-skip-provisional", help="Include <180 provisional SIP responses", action="store_true")
    parser.add_argument("--add-participants", help="Declare participants with names", action="store_true")
    parser.add_argument("--autonumber", help="Enable Mermaid autonumbering", action="store_true")
    parser.add_argument("--filter-method", help="Comma-separated list of SIP methods (e.g., INVITE,BYE)", default=None)
    parser.add_argument("--filter-status", help="Comma-separated list of SIP status codes (e.g., 200,486)", default=None)
    parser.add_argument("--add-time", help="Annotate each message with packet timestamp", action="store_true")
    parser.add_argument("--summary-table", help="Add a summary table of participant names to output", action="store_true")
    parser.add_argument("--logfile", help="Save log messages to a file", default=None)
    parser.add_argument("--verbose", help="Show debug log messages", action="store_true")
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    if args.logfile:
        logging.basicConfig(filename=args.logfile, level=log_level, format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    logger = logging.getLogger("pcap2mermaid")

    check_input_output_files(args.infile, args.outfile)

    # Parse host:port -> name mapping
    host2name = parse_mapping(args.mapping)
    filter_unmapped = bool(args.mapping)

    # Parse participant-names CSV if set (overrides mapping)
    if args.participant_names:
        host2name = parse_participant_csv(args.participant_names)
        filter_unmapped = bool(host2name)  # If CSV provided, only use mapped

    # Parse filters
    method_filter = [m.strip().upper() for m in args.filter_method.split(",")] if args.filter_method else None
    status_filter = [s.strip() for s in args.filter_status.split(",")] if args.filter_status else None

    # Main packet processing
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

    # Participant naming logic
    if args.add_participants:
        if host2name:
            # If mapping, use mapped names as participants
            participant_map = {p: host2name[p] for p in all_participants if p in host2name}
            named_participants = set(participant_map.values())
        else:
            # Assign default names
            participant_map = assign_participant_names(all_participants)
            named_participants = set(participant_map.values())
    else:
        participant_map = host2name if filter_unmapped else {}

    # Write output (stream for memory efficiency)
    with open(args.outfile, "w") as outfh:
        outfh.write("sequenceDiagram\n")
        if args.autonumber:
            outfh.write("    autonumber\n")
        # Output participant declarations if requested
        if args.add_participants:
            declared = set()
            for p in sorted(all_participants):
                pname = participant_map[p] if p in participant_map else p
                if pname not in declared:
                    outfh.write(f"    participant {pname}\n")
                    declared.add(pname)
        # Output SIP messages
        for pkt in sip_packets:
            a, b = pkt['src'], pkt['dst']
            # Filtering for mapping
            if filter_unmapped and (a not in host2name or b not in host2name):
                continue
            # Use participant names if set (mapping or default)
            a_out = participant_map[a] if a in participant_map else a
            b_out = participant_map[b] if b in participant_map else b
            arrow = "->>" if pkt['req'] else "-->>"
            msg = pkt['text']
            if args.add_time:
                msg = f"[{pkt['time']:.3f}] {msg}"
            outfh.write(f"    {a_out}{arrow}{b_out}: {msg}\n")
            seq_count += 1

    # Optional summary table
    if args.summary_table and args.add_participants:
        output_summary_table(args.outfile, participant_map)

    # Print summary
    logger.info(f"Done, {seq_count} SIP packets written to sequence diagram: {args.outfile}")
    logger.info(f"Processed {pkt_count} packets, dropped {dropped} packets for these reasons: {dropped_reasons}")

    # Mapping consistency warnings
    if filter_unmapped:
        all_mapped = set(host2name.keys())
        seen = all_participants
        unused = all_mapped - seen
        if unused:
            logger.warning(f"The following mappings in --mapping/CSV were never seen in the pcap: {unused}")
        unseen = seen - all_mapped
        if unseen:
            logger.warning(f"The following participants were seen in pcap but not mapped: {unseen}")

if __name__ == "__main__":
    main()
