cd /home/project/widget-log-checker || exit 1

# deps
cat > requirements.txt <<'REQ'
python-dotenv==1.0.1
mysql-connector-python==9.0.0
REQ

# venv + install
test -d venv || python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
