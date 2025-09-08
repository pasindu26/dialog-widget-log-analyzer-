cat > ingest.py <<'PY'
#!/usr/bin/env python3
import os, sys, re, hashlib, logging
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit
from dotenv import load_dotenv
import mysql.connector
from logging.handlers import RotatingFileHandler

def setup_logger(log_dir: Path):
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "ingest.log"
    logger = logging.getLogger("ingest")
    logger.setLevel(logging.INFO)
    fh = RotatingFileHandler(log_path, maxBytes=10_000_000, backupCount=7)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh.setFormatter(fmt)
    logger.handlers.clear()
    logger.addHandler(fh)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger

def parse_time_iso(raw):
    t = raw.strip()
    if t.startswith('[') and t.endswith(']'): t = t[1:-1]
    try:
        dt = datetime.strptime(t, '%d/%b/%Y:%H:%M:%S %z')
        return dt.isoformat(timespec='seconds'), dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        return raw, None

def split_request(req):
    m = re.match(r'^(\S+)\s+(\S+)\s+(HTTP/\d(?:\.\d)?)$', req)
    if not m: return '', '', '', ''
    method, target, http_version = m.groups()
    parts = urlsplit(target)
    path = parts.path or ''
    query_string = ('?' + parts.query) if parts.query else ''
    return method, path, http_version, query_string

def db_connect(env):
    conn = mysql.connector.connect(
        host=env['DB_HOST'], port=int(env['DB_PORT']),
        user=env['DB_USER'], password=env['DB_PASSWORD'],
        autocommit=False
    )
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{env['DB_NAME']}` "
                "DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_unicode_ci;")
    cur.execute(f"USE `{env['DB_NAME']}`;")
    cur.close(); conn.commit()
    return conn

def ensure_tables(conn):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS proxy_logs (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      line_hash CHAR(40) NOT NULL,
      vhost VARCHAR(255), remote_host VARCHAR(255), x_forwarded_for VARCHAR(255),
      time_iso VARCHAR(35), time_utc DATETIME,
      method VARCHAR(16), path TEXT, http_version VARCHAR(16), query_string TEXT,
      status INT, bytes BIGINT, time_us BIGINT,
      idm_trf_i VARCHAR(64), idm_srf_i VARCHAR(64), idm_trf_o VARCHAR(64), idm_srf_o VARCHAR(64),
      referer TEXT, user_agent TEXT,
      PRIMARY KEY (id),
      UNIQUE KEY uq_line_hash (line_hash),
      KEY idx_time_utc (time_utc),
      KEY idx_vhost_status (vhost, status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ingest_state (
      file_path VARCHAR(512) NOT NULL,
      inode BIGINT UNSIGNED, last_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
      last_mtime DATETIME, last_hash CHAR(40),
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (file_path)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ingest_audit (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      file_path VARCHAR(512) NOT NULL,
      started_at DATETIME NOT NULL, ended_at DATETIME,
      lines_read BIGINT UNSIGNED NOT NULL DEFAULT 0,
      lines_inserted BIGINT UNSIGNED NOT NULL DEFAULT 0,
      lines_skipped BIGINT UNSIGNED NOT NULL DEFAULT 0,
      errors BIGINT UNSIGNED NOT NULL DEFAULT 0,
      note TEXT,
      PRIMARY KEY (id),
      KEY idx_file_time (file_path, started_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    cur.close(); conn.commit()

def get_state(conn, path_str):
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT inode,last_offset,last_mtime,last_hash FROM ingest_state WHERE file_path=%s", (path_str,))
    row = cur.fetchone(); cur.close()
    return row

def upsert_state(conn, path_str, inode, offset, mtime_dt, last_hash):
    cur = conn.cursor()
    cur.execute("""
      INSERT INTO ingest_state (file_path,inode,last_offset,last_mtime,last_hash)
      VALUES (%s,%s,%s,%s,%s)
      ON DUPLICATE KEY UPDATE inode=VALUES(inode),last_offset=VALUES(last_offset),
                              last_mtime=VALUES(last_mtime),last_hash=VALUES(last_hash)
    """, (path_str, inode, offset, mtime_dt, last_hash))
    cur.close(); conn.commit()

def audit_start(conn, file_path):
    cur = conn.cursor()
    cur.execute("INSERT INTO ingest_audit (file_path, started_at) VALUES (%s, NOW())", (file_path,))
    rid = cur.lastrowid; cur.close(); conn.commit(); return rid

def audit_finish(conn, rid, r, i, s, e, note=None):
    cur = conn.cursor()
    cur.execute("""
      UPDATE ingest_audit SET ended_at=NOW(),
        lines_read=%s, lines_inserted=%s, lines_skipped=%s, errors=%s, note=%s
      WHERE id=%s
    """, (r,i,s,e,note,rid))
    cur.close(); conn.commit()

def parse_line(raw_line):
    if '|' not in raw_line: return None
    parts = raw_line.split('|')
    # new format
    if len(parts) >= 14:
        vhost, remote_host, xff, t_raw, req, status, bytes_sent, time_us, idm_trf_i, idm_srf_i, idm_trf_o, idm_srf_o, referer = parts[:13]
        user_agent = '|'.join(parts[13:])
        if re.match(r'^\[.*\+\d{4}\]$', t_raw.strip()):
            t_iso, t_utc = parse_time_iso(t_raw)
            method, path, http_version, qs = split_request(req)
            return dict(
                vhost=vhost, remote_host=remote_host, x_forwarded_for=xff,
                time_iso=t_iso, time_utc=t_utc,
                method=method, path=path, http_version=http_version, query_string=qs,
                status=int(status) if status.isdigit() else None,
                bytes=None if bytes_sent=='-' else int(bytes_sent) if bytes_sent.isdigit() else None,
                time_us=int(time_us) if time_us.isdigit() else None,
                idm_trf_i=idm_trf_i, idm_srf_i=idm_srf_i, idm_trf_o=idm_trf_o, idm_srf_o=idm_srf_o,
                referer=None if referer=='-' else referer, user_agent=user_agent
            )
    # old format
    if len(parts) >= 15:
        try:
            vhost, remote_host, xff, _c1, _c2, t_raw, req, qs_old, status, bytes_old, time_us, referer, idm_trf_old, idm_srf_old = parts[:14]
            user_agent = '|'.join(parts[14:])
        except ValueError:
            return None
        if re.match(r'^\[.*\+\d{4}\]$', t_raw.strip()):
            t_iso, t_utc = parse_time_iso(t_raw)
            method, path, http_version, qs_from_req = split_request(req)
            qs = qs_old if qs_old else qs_from_req
            return dict(
                vhost=vhost, remote_host=remote_host, x_forwarded_for=xff,
                time_iso=t_iso, time_utc=t_utc,
                method=method, path=path, http_version=http_version, query_string=qs,
                status=int(status) if status.isdigit() else None,
                bytes=None if bytes_old=='-' else int(bytes_old) if bytes_old.isdigit() else None,
                time_us=int(time_us) if time_us.isdigit() else None,
                idm_trf_i=idm_trf_old, idm_srf_i='', idm_trf_o='', idm_srf_o=idm_srf_old,
                referer=None if referer=='-' else referer, user_agent=user_agent
            )
    return None

def insert_one(conn, row, line_hash):
    sql = ("""
      INSERT IGNORE INTO proxy_logs
      (line_hash,vhost,remote_host,x_forwarded_for,time_iso,time_utc,
       method,path,http_version,query_string,status,bytes,time_us,
       idm_trf_i,idm_srf_i,idm_trf_o,idm_srf_o,referer,user_agent)
      VALUES
      (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """)
    cur = conn.cursor(prepared=True)
    cur.execute(sql, (
        line_hash, row['vhost'], row['remote_host'], row['x_forwarded_for'],
        row['time_iso'], row['time_utc'],
        row['method'], row['path'], row['http_version'], row['query_string'],
        row['status'], row['bytes'], row['time_us'],
        row['idm_trf_i'], row['idm_srf_i'], row['idm_trf_o'], row['idm_srf_o'],
        row['referer'], row['user_agent']
    ))
    conn.commit()
    affected = cur.rowcount
    cur.close()
    return affected

def run_once(env):
    logger = setup_logger(Path(env['OUTPUT_DIR']))
    logger.info("Ingest run started")

    conn = db_connect(env); ensure_tables(conn)

    logs_dir = Path(env['LOGS_DIR'])
    if not logs_dir.is_dir():
        logger.error(f"Logs dir not found: {logs_dir}"); return 1

    total_r=total_i=total_s=total_e=0

    for path in sorted(logs_dir.iterdir(), key=lambda p: p.name):
        if not path.is_file(): continue
        stat = path.stat()
        size, inode = stat.st_size, getattr(stat, 'st_ino', None)
        mtime_dt = datetime.fromtimestamp(stat.st_mtime)

        pstr = str(path)
        st = get_state(conn, pstr)
        offset = 0; reset=None
        if st:
            last_off = int(st['last_offset'])
            last_inode = st['inode']
            if size < last_off:
                offset=0; reset="truncated"
            elif last_inode is not None and inode is not None and inode != last_inode:
                offset=0; reset="rotated"
            else:
                offset=last_off

        audit_id = audit_start(conn, pstr)
        logger.info(f"Processing {path.name} from offset {offset}/{size}" + (f" (reset={reset})" if reset else ""))

        r=i=s=e=0; last_hash=None
        try:
            with open(path, 'rb') as fb:
                fb.seek(offset)
                while True:
                    chunk = fb.readline()
                    if not chunk: break
                    try:
                        line = chunk.decode('utf-8', errors='replace').rstrip('\n')
                    except Exception:
                        line = chunk.decode('latin-1', errors='replace').rstrip('\n')

                    r += 1
                    row = parse_line(line)
                    if row is None:
                        s += 1
                        continue
                    line_hash = hashlib.sha1(line.encode('utf-8', errors='replace')).hexdigest()
                    affected = insert_one(conn, row, line_hash)
                    i += affected
                    last_hash = line_hash

                new_off = fb.tell()
                upsert_state(conn, pstr, inode, new_off, mtime_dt, last_hash)
        except Exception as ex:
            e += 1
            logger.exception(f"Error processing {pstr}: {ex}")

        audit_finish(conn, audit_id, r, i, s, e)
        logger.info(f"Done {path.name}: read={r} inserted={i} skipped={s} errors={e}")
        total_r+=r; total_i+=i; total_s+=s; total_e+=e

    conn.close()
    logger.info(f"Ingest finished: total_read={total_r} inserted={total_i} skipped={total_s} errors={total_e}")
    return 0

def load_env():
    load_dotenv(override=True)
    return {
        'DB_HOST': os.getenv('DB_HOST','127.0.0.1'),
        'DB_PORT': os.getenv('DB_PORT','3306'),
        'DB_NAME': os.getenv('DB_NAME','widgetlogs'),
        'DB_USER': os.getenv('DB_USER','wbuser'),
        'DB_PASSWORD': os.getenv('DB_PASSWORD',''),
        'LOGS_DIR': os.getenv('LOGS_DIR','./logs'),
        'OUTPUT_DIR': os.getenv('OUTPUT_DIR','./output'),
    }

if __name__ == "__main__":
    env = load_env()
    sys.exit(run_once(env))
PY

chmod +x ingest.py
