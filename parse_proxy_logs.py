#!/usr/bin/env python3
import os, sys, csv, re, argparse, gzip
from pathlib import Path
from datetime import datetime
from urllib.parse import urlsplit

# Final unified CSV schema (matches new format; backfills old format where possible)
HEADER = [
    'vhost','remote_host','x_forwarded_for','time',
    'method','path','http_version','query_string',
    'status','bytes','time_us',
    'idm_trf_i','idm_srf_i','idm_trf_o','idm_srf_o',
    'referer','user_agent'
]

MONTH_MAP = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05',
             'Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}

def parse_time_iso(raw):
    # raw example: "[04/Sep/2025:05:30:14 +0530]"
    t = raw.strip()
    if t.startswith('[') and t.endswith(']'):
        t = t[1:-1]
    try:
        dt = datetime.strptime(t, '%d/%b/%Y:%H:%M:%S %z')
        return dt.isoformat(timespec='seconds')
    except Exception:
        return raw  # fallback (still writeable)

def date_from_time(raw, iso):
    if iso and re.match(r'^\d{4}-\d{2}-\d{2}T', iso):
        return iso[:10]
    m = re.search(r'(\d{2})/([A-Za-z]{3})/(\d{4})', raw)
    if not m:
        return 'unknown'
    d, mon, y = m.groups()
    return f"{y}-{MONTH_MAP.get(mon, '01')}-{d.zfill(2)}"

def split_request(req):
    # "GET /path?x=y HTTP/1.1"
    m = re.match(r'^(\S+)\s+(\S+)\s+(HTTP/\d(?:\.\d)?)$', req)
    if not m:
        return '', '', '', ''
    method, target, http_version = m.groups()
    parts = urlsplit(target)
    path = parts.path or ''
    query_string = ('?' + parts.query) if parts.query else ''
    return method, path, http_version, query_string

def iter_lines(path):
    opener = gzip.open if str(path).endswith('.gz') else open
    try:
        with opener(path, 'rt', encoding='utf-8', errors='replace') as f:
            for line in f:
                yield line.rstrip('\n')
    except Exception as e:
        print(f"Warning: could not read {path}: {e}", file=sys.stderr)

def main(logs_dir, output_dir):
    logs_dir = Path(logs_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    writers, files = {}, {}
    def get_writer(date_str):
        if date_str not in writers:
            out_path = output_dir / f'proxy_log_{date_str}.csv'
            f = open(out_path, 'a', newline='', encoding='utf-8')
            w = csv.DictWriter(f, fieldnames=HEADER, quoting=csv.QUOTE_MINIMAL)
            if f.tell() == 0:
                w.writeheader()
            writers[date_str] = w
            files[date_str] = f
        return writers[date_str]

    processed = skipped = 0
    count_14 = count_15 = count_other = 0

    for entry in sorted(logs_dir.iterdir(), key=lambda p: p.name):
        if not entry.is_file():
            continue
        for line in iter_lines(entry):
            if not line or '|' not in line:
                continue

            parts = line.split('|')
            # (No mandatory trailing '|' in new format; keep everything as-is)

            row = None
            date_for_file = None

            # --- NEW FORMAT: 14+ fields ---
            if len(parts) >= 14:
                # Map first 13 exactly, then join the rest into user_agent (handles rare '|' in UA)
                vhost          = parts[0]
                remote_host    = parts[1]
                xff            = parts[2]
                t_raw          = parts[3]
                req            = parts[4]
                status         = parts[5]
                bytes_sent     = parts[6]
                time_us        = parts[7]
                idm_trf_i      = parts[8]
                idm_srf_i      = parts[9]
                idm_trf_o      = parts[10]
                idm_srf_o      = parts[11]
                referer        = parts[12]
                user_agent     = '|'.join(parts[13:])  # safe join

                # Heuristic: ensure this is the new format by checking time token looks like [..:.. +zzzz]
                if re.match(r'^\[.*\+\d{4}\]$', t_raw.strip()):
                    t_iso = parse_time_iso(t_raw)
                    date_for_file = date_from_time(t_raw, t_iso)
                    method, path, http_version, qs = split_request(req)
                    row = {
                        'vhost': vhost,
                        'remote_host': remote_host,
                        'x_forwarded_for': xff,
                        'time': t_iso,
                        'method': method,
                        'path': path,
                        'http_version': http_version,
                        'query_string': qs,
                        'status': status,
                        'bytes': '' if bytes_sent == '-' else bytes_sent,
                        'time_us': time_us,
                        'idm_trf_i': idm_trf_i,
                        'idm_srf_i': idm_srf_i,
                        'idm_trf_o': idm_trf_o,
                        'idm_srf_o': idm_srf_o,
                        'referer': '' if referer == '-' else referer,
                        'user_agent': user_agent,
                    }
                    count_14 += 1

            # --- OLD FORMAT fallback: 15+ fields with %q, %b, cf_* (kept for mixed dirs) ---
            if row is None and len(parts) >= 15:
                try:
                    vhost, remote_host, xff, _cf_country, _cf_conn_ip, t_raw, req, qs_old, status, bytes_sent_old, time_us, referer, idm_trf_old, idm_srf_old = parts[:14]
                    user_agent = '|'.join(parts[14:])
                except ValueError:
                    pass
                else:
                    if re.match(r'^\[.*\+\d{4}\]$', t_raw.strip()):
                        t_iso = parse_time_iso(t_raw)
                        date_for_file = date_from_time(t_raw, t_iso)
                        method, path, http_version, qs_from_req = split_request(req)
                        qs = qs_old if qs_old else qs_from_req
                        row = {
                            'vhost': vhost,
                            'remote_host': remote_host,
                            'x_forwarded_for': xff,
                            'time': t_iso,
                            'method': method,
                            'path': path,
                            'http_version': http_version,
                            'query_string': qs,
                            'status': status,
                            'bytes': '' if bytes_sent_old == '-' else bytes_sent_old,
                            'time_us': time_us,
                            'idm_trf_i': idm_trf_old,  # best-effort mapping
                            'idm_srf_i': '',
                            'idm_trf_o': '',
                            'idm_srf_o': idm_srf_old,  # best-effort mapping
                            'referer': '' if referer == '-' else referer,
                            'user_agent': user_agent,
                        }
                        count_15 += 1

            if row is None or date_for_file is None:
                skipped += 1
                count_other += 1
                continue

            writer = get_writer(date_for_file)
            writer.writerow(row)
            processed += 1

    for f in files.values():
        f.close()

    print(
        f"Done. Processed {processed} lines, skipped {skipped}. "
        f"(new14={count_14}, old15={count_15}, other={count_other}) Output: {output_dir}",
        file=sys.stderr
    )

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Parse Apache pipe-delimited logs (new 14-field & old 15-field) to per-day CSV.')
    ap.add_argument('--logs-dir', default='./logs', help='Input logs directory (default: ./logs)')
    ap.add_argument('--output-dir', default='./output', help='Output directory (default: ./output)')
    args = ap.parse_args()
    main(args.logs_dir, args.output_dir)
