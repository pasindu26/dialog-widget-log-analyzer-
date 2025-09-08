cd /home/project/widget-log-checker || exit 1

# verify logs dir exists
test -d logs && echo "[OK] logs dir found: $(readlink -f logs)" || { echo "[ERROR] logs dir missing"; ls -l; exit 1; }

# create .env (edit DB_PASSWORD if yours is different)
cat > .env <<'EOF'
# --- MySQL connection ---
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=widgetlogs
DB_USER=wbuser
DB_PASSWORD=Another_Str0ng_Pass!

# --- parser options ---
LOGS_DIR=/home/project/widget-log-checker/logs
OUTPUT_DIR=/home/project/widget-log-checker/output
WRITE_CSV=true
BATCH_SIZE=1000
EOF

# show it back (mask password)
echo "----- .env -----"
sed 's/^DB_PASSWORD=.*/DB_PASSWORD=********/' .env
