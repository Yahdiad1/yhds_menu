#!/usr/bin/env bash
# YHDS ALL-IN-ONE INSTALLER (Menu + create scripts + nginx + xray minimal)
# Run as root on Debian/Ubuntu
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# -------- CONFIG ----------
BIN=/usr/local/bin
WWW=/var/www/html
YDIR=/usr/local/etc/yhds
DB=/etc/yhds/users.csv
XRAY_BIN=/usr/local/bin/xray
XRAY_SYSTEMD=/etc/systemd/system/xray.service
XRAY_CONF=/usr/local/etc/xray/config.json
NG_CONF=/etc/nginx/sites-available/yhds_payloads
BACKUP_DIR=/usr/local/bin/yhds_backups_$(date +%Y%m%d-%H%M%S)
IP_PUB=$(curl -s --max-time 2 ipv4.icanhazip.com || hostname -I | awk '{print $1}')
# ---------------------------

if [[ $EUID -ne 0 ]]; then
  echo "Run as root!"
  exit 1
fi

mkdir -p "$BIN" "$WWW" "$YDIR" "$BACKUP_DIR"
chmod 755 "$BIN" "$WWW" "$YDIR"

echo "Backing up important files to $BACKUP_DIR ..."
for f in /usr/local/bin/menu /usr/local/bin/create_*.sh /usr/local/bin/install_telegram_bot.sh /usr/local/bin/yhds_telegram_send.sh $XRAY_CONF $XRAY_BIN $XRAY_SYSTEMD; do
  [ -e "$f" ] && cp -a "$f" "$BACKUP_DIR/$(basename $f).bak" 2>/dev/null || true
done

# 1) Basic packages
echo "Installing dependencies..."
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y curl wget jq unzip tar openssl gnupg ca-certificates lsb-release iproute2 coreutils procps net-tools sed awk grep at nginx python3 python3-pip openssh-server dropbear >/dev/null 2>&1 || true

# Ensure 'at' service
systemctl enable --now atd >/dev/null 2>&1 || true

# 2) Setup nginx site port 81 for payloads (idempotent)
cat > "$NG_CONF" <<'NG'
server {
    listen 81 default_server;
    listen [::]:81 default_server;
    root /var/www/html;
    index index.html;
    server_name _;
    access_log /var/log/nginx/yhds_access.log;
    error_log  /var/log/nginx/yhds_error.log;
    location / { try_files $uri $uri/ =404; }
}
NG
ln -sf "$NG_CONF" /etc/nginx/sites-enabled/yhds_payloads
# remove default to avoid duplicate default server conflict on :81
if [[ -f /etc/nginx/sites-enabled/default ]]; then
  rm -f /etc/nginx/sites-enabled/default || true
fi
nginx -t >/dev/null 2>&1 || true
systemctl restart nginx >/dev/null 2>&1 || true

# 3) Create DB header if missing
if [[ ! -f "$DB" ]]; then
  echo "username,password,created,service,max_login" > "$DB"
  chmod 600 "$DB"
fi

# 4) Telegram helper
cat > "$BIN/yhds_telegram_send.sh" <<'SH'
#!/usr/bin/env bash
CFG="/etc/yhds/telegram.json"
if [ ! -f "$CFG" ]; then exit 0; fi
TOKEN=$(jq -r .token "$CFG" 2>/dev/null || echo "")
CHAT_ID=$(jq -r .chat_id "$CFG" 2>/dev/null || echo "")
TEXT="$1"
MODE="${2:-text}"
if [ -n "$TOKEN" ] && [ -n "$CHAT_ID" ]; then
  if [ "${MODE}" = "html" ]; then
    curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" -d parse_mode="HTML" --data-urlencode "text=${TEXT}" >/dev/null 2>&1 || true
  else
    curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" --data-urlencode "text=${TEXT}" >/dev/null 2>&1 || true
  fi
fi
SH
chmod +x "$BIN/yhds_telegram_send.sh"

cat > "$BIN/install_telegram_bot.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
CFG="/etc/yhds/telegram.json"
mkdir -p /etc/yhds
read -p "Enter BOT_TOKEN (from @BotFather): " B
read -p "Enter CHAT_ID (your chat id): " C
if [ -z "$B" ] || [ -z "$C" ]; then
  echo "Cancel: token or chat id empty"; exit 1
fi
cat > "$CFG" <<JSON
{"token":"$B","chat_id":"$C"}
JSON
chmod 600 "$CFG"
echo "Saved $CFG"
SH
chmod +x "$BIN/install_telegram_bot.sh"

# 5) Common header for create scripts
COMMON_HEADER='#!/usr/bin/env bash
set -euo pipefail
WWW=/var/www/html
DB=/etc/yhds/users.csv
LAST=/tmp/last_payload.txt
now(){ date +"%d %b, %Y %H:%M:%S"; }
randpw(){ head /dev/urandom | tr -dc "a-z0-9" | head -c10 || echo "orderyuk"; }
pubip(){ curl -s --max-time 2 ipv4.icanhazip.com || hostname -I | awk '"'"'{print $1}'"'"'; }
mkdir -p "$WWW"
touch "$DB"
'

# 6) create_ssh.sh (manual + trial)
cat > "$BIN/create_ssh.sh" <<'SSH'
'"$COMMON_HEADER"'
# create_ssh.sh
MODE="${1:-}"
if [[ "$MODE" == "normal" ]]; then
  USER="${2:-}"; PASS="${3:-}"; DAYS="${4:-}"; MAXLOGIN="${5:-}"
  if [[ -z "$USER" ]]; then read -p "Username: " USER; fi
  if [[ -z "$PASS" ]]; then read -p "Password: " PASS; fi
  if [[ -z "$DAYS" ]]; then read -p "Masa aktif (hari, empty=permanent): " DAYS; fi
  if [[ -z "$MAXLOGIN" ]]; then read -p "Max concurrent login (empty=0 unlimited): " MAXLOGIN; fi
  HOST="${6:-$(pubip)}"

  if ! id "$USER" >/dev/null 2>&1; then
    if [[ "$DAYS" =~ ^[0-9]+$ ]]; then
      EXP=$(date -d "+$DAYS days" +%F 2>/dev/null || true)
      useradd -M -s /usr/sbin/nologin -e "$EXP" "$USER" 2>/dev/null || useradd -M -s /bin/false -e "$EXP" "$USER" 2>/dev/null || true
    else
      useradd -M -s /usr/sbin/nologin "$USER" 2>/dev/null || useradd -M -s /bin/false "$USER" 2>/dev/null || true
    fi
  fi
  echo "${USER}:${PASS}" | chpasswd 2>/dev/null || true

  OUT="$WWW/ssh-${USER}.txt"
  cat > "$OUT" <<EOF
SSH Account
-----------------------------------------
Host             : ${HOST}
Username         : ${USER}
Password         : ${PASS}
-----------------------------------------
Max login        : ${MAXLOGIN:-unlimited}
Masa aktif       : $( if [[ "$DAYS" =~ ^[0-9]+$ ]]; then echo "${DAYS} Hari"; else echo "Permanent"; fi )
Port OpenSSH     : 22
Port SSH UDP     : 1-65535
Port Dropbear    : 109,110
Port SSH WS      : 8080
Port SSH WSS     : 8443
Port SSL/TLS     : 444
-----------------------------------------
HTTP CUSTOM      : ${HOST}:1-65535@${USER}:${PASS}
-----------------------------------------
Payload          : GET /cdn-cgi/trace HTTP/1.1[crlf]Host: Bug_Kalian[crlf][crlf]GET-RAY / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]
-----------------------------------------
Save Link Account: http://${HOST}:81/$(basename "$OUT")
-----------------------------------------
Dibuat Pada      : $(now)
EOF

  chmod 644 "$OUT" || true
  if ! head -n1 "$DB" | grep -q "max_login"; then
    (echo "username,password,created,service,max_login") > "$DB.tmp" && tail -n +2 "$DB" >> "$DB.tmp" 2>/dev/null || cp "$DB" "$DB.tmp" || true
    mv -f "$DB.tmp" "$DB" 2>/dev/null || true
  fi
  echo "${USER},${PASS},$(date +%F' '%T),ssh,${MAXLOGIN:-0}" >> "$DB"
  if [[ -f "$OUT" ]]; then cat "$OUT" > "$LAST" || true; fi
  echo "=> SSH created: ${USER}"
  cat "$OUT"
  exit 0

elif [[ "$MODE" == "trial" ]]; then
  MIN="${2:-60}"
  USER="TrialSSH$(shuf -i1000-9999 -n1)"
  PASS="$(randpw)"
  HOST="$(pubip)"
  OUT="$WWW/ssh-${USER}.txt"
  cat > "$OUT" <<EOF
Trial SSH Account
-----------------------------------------
Host             : ${HOST}
Username         : ${USER}
Password         : ${PASS}
Duration         : ${MIN} minutes
Port OpenSSH     : 22
Port SSH UDP     : 1-65535
Port SSH WS      : 8080
Port SSH WSS     : 8443
-----------------------------------------
Payload (WS):
GET /cdn-cgi/trace HTTP/1.1[crlf]Host: Bug_Kalian[crlf][crlf]GET-RAY / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]
-----------------------------------------
File: http://${HOST}:81/$(basename "$OUT")
Created: $(now)
EOF
  chmod 644 "$OUT" || true
  echo "${USER},${PASS},$(date +%F' '%T),ssh_trial,0" >> "$DB"
  if [[ -f "$OUT" ]]; then cat "$OUT" > "$LAST" || true; fi
  if command -v at >/dev/null 2>&1; then
    echo "userdel -f ${USER} 2>/dev/null || true; sed -i '/^${USER},/d' ${DB}; rm -f ${OUT}" | at now + "${MIN}" minutes
  fi
  echo "=> SSH trial created: ${USER}"
  cat "$OUT"
  exit 0
else
  echo "Usage: $0 normal [username] [password] [days] [max_login]"
  echo "       $0 trial [minutes]"
  read -p "Mode (1 normal / 2 trial) [1]: " c || true
  if [[ "$c" == "2" ]]; then exec "$0" trial; else exec "$0" normal; fi
fi
SSH
chmod +x "$BIN/create_ssh.sh"

# 7) create_udp.sh
cat > "$BIN/create_udp.sh" <<'UDP'
'"$COMMON_HEADER"'
MODE="${1:-}"
if [[ "$MODE" == "normal" ]]; then
  U="${2:-}"; S="${3:-}"; MAXLOGIN="${4:-}"
  if [[ -z "$U" ]]; then read -p "Remarks/Username: " U; fi
  S=${S:-$(head /dev/urandom | tr -dc "a-z0-9" | head -c12 || echo "udpordy")}
  HOST="${5:-$(pubip)}"
  OUT="$WWW/udp-${U}.txt"
  cat > "$OUT" <<EOF
UDP Custom Account
-----------------------------------------
Host/IP : ${HOST}
User    : ${U}
Secret  : ${S}
Port    : 1-65535
Max login: ${MAXLOGIN:-unlimited}
-----------------------------------------
Saved: ${OUT}
Created: $(now)
EOF
  chmod 644 "$OUT" || true
  if ! head -n1 "$DB" | grep -q "max_login"; then
    (echo "username,password,created,service,max_login") > "$DB.tmp" && tail -n +2 "$DB" >> "$DB.tmp" 2>/dev/null || cp "$DB" "$DB.tmp" || true
    mv -f "$DB.tmp" "$DB" 2>/dev/null || true
  fi
  echo "${U},${S},$(date +%F' '%T),udp,${MAXLOGIN:-0}" >> "$DB"
  if [[ -f "$OUT" ]]; then cat "$OUT" > "$LAST" || true; fi
  echo "=> UDP created: ${U}"
  cat "$OUT"
  exit 0

elif [[ "$MODE" == "trial" ]]; then
  MIN="${2:-60}"
  U="udptr$(shuf -i1000-9999 -n1)"
  S="$(head /dev/urandom | tr -dc "a-z0-9" | head -c12 || echo "udpordy")"
  HOST="$(pubip)"
  OUT="$WWW/udp-${U}.txt"
  cat > "$OUT" <<EOF
UDP Trial Account
-----------------------------------------
Host/IP : ${HOST}
User    : ${U}
Secret  : ${S}
Port    : 1-65535
Duration: ${MIN} minutes (trial)
-----------------------------------------
Saved: ${OUT}
Created: $(now)
EOF
  chmod 644 "$OUT" || true
  echo "${U},${S},$(date +%F' '%T),udp_trial,0" >> "$DB"
  if [[ -f "$OUT" ]]; then cat "$OUT" > "$LAST" || true; fi
  if command -v at >/dev/null 2>&1; then
    echo "sed -i '/^${U},/d' ${DB}; rm -f ${OUT}" | at now + "${MIN}" minutes
  fi
  echo "=> UDP trial created: ${U}"
  cat "$OUT"
  exit 0
else
  echo "Usage: $0 normal [username] [secret] [max_login]  OR  $0 trial [minutes]"
  read -p "Mode (1 normal / 2 trial) [1]: " c || true
  if [[ "$c" == "2" ]]; then exec "$0" trial; else exec "$0" normal; fi
fi
UDP
chmod +x "$BIN/create_udp.sh"

# 8) create_trojan.sh (inject minimal inbound into xray config if installed)
cat > "$BIN/create_trojan.sh" <<'TR'
'"$COMMON_HEADER"'
MODE="${1:-}"
gen_pw(){ if command -v uuidgen >/dev/null 2>&1; then uuidgen; else cat /proc/sys/kernel/random/uuid; fi }
XRAY_CFG="/usr/local/etc/xray/config.json"
if [[ -f "$XRAY_CFG" ]]; then XRAY_EXISTS=1; else XRAY_EXISTS=0; fi

if [[ "$MODE" == "normal" ]]; then
  U="${2:-}"; P="${3:-}"; MAXLOGIN="${4:-}"
  if [[ -z "$U" ]]; then read -p "Remarks/Username: " U; fi
  P=${P:-$(gen_pw)}
  HOST="${5:-$(pubip)}"
  PATH_WS="${6:-trojan-ws}"
  PORT="${7:-443}"
  OUT="$WWW/trojan-${U}.txt"
  cat > "$OUT" <<EOF
Trojan Account
-----------------------------------------
Remarks    : ${U}
Host/IP    : ${HOST}
Password   : ${P}
Path       : /${PATH_WS}
Port       : ${PORT} (ws+tls)
Max login  : ${MAXLOGIN:-unlimited}
-----------------------------------------
Link TLS (WS):
trojan://${P}@${HOST}:${PORT}?path=%2F${PATH_WS}&security=tls&type=ws#${U}
-----------------------------------------
Saved: http://${HOST}:81/$(basename "$OUT")
Created: $(now)
EOF
  chmod 644 "$OUT" || true
  if ! head -n1 "$DB" | grep -q "max_login"; then
    (echo "username,password,created,service,max_login") > "$DB.tmp" && tail -n +2 "$DB" >> "$DB.tmp" 2>/dev/null || cp "$DB" "$DB.tmp" || true
    mv -f "$DB.tmp" "$DB" 2>/dev/null || true
  fi
  echo "${U},${P},$(date +%F' '%T),trojan,${MAXLOGIN:-0}" >> "$DB"
  if [[ -f "$OUT" ]]; then cat "$OUT" > "$LAST" || true; fi

  # Try injecting into xray config (best-effort)
  if [[ $XRAY_EXISTS -eq 1 ]]; then
    cp -a "$XRAY_CFG" "${XRAY_CFG}.bak.$(date +%s)" 2>/dev/null || true
    python3 - <<PY || true
import json,sys
cfg="$XRAY_CFG"
try:
  j=json.load(open(cfg,'r',encoding='utf-8'))
except:
  j={"inbounds":[],"outbounds":[{"protocol":"freedom","settings":{}}]}
trojan_inbound = {
  "port": int($PORT),
  "protocol": "trojan",
  "settings": {"clients":[{"password":"'"$P"'","flow":""}]},
  "streamSettings": {"network":"ws","security":"tls","wsSettings":{"path":"/'"$PATH_WS"'","headers":{}},"tlsSettings":{"certificates":[{"certificateFile":"/etc/ssl/xray/trojan.crt","keyFile":"/etc/ssl/xray/trojan.key"}]}},
  "tag":"trojan-ws-in"
}
# append inbound
inb=j.setdefault("inbounds",[])
inb.append(trojan_inbound)
open(cfg,'w',encoding='utf-8').write(json.dumps(j,indent=2))
print("INJECT_OK")
PY
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart xray 2>/dev/null || true
  fi

  echo "=> Trojan created: ${U}"
  cat "$OUT"
  exit 0

elif [[ "$MODE" == "trial" ]]; then
  MIN="${2:-30}"
  U="trojan$(shuf -i1000-9999 -n1)"
  P="$(gen_pw)"
  HOST="$(pubip)"
  PATH_WS="trojan-ws"
  PORT=443
  OUT="$WWW/trojan-${U}.txt"
  cat > "$OUT" <<EOF
Trial Trojan Account
-----------------------------------------
Remarks          : ${U}
Host/IP          : ${HOST}
Password         : ${P}
Path             : /${PATH_WS}
Port             : ${PORT} (ws+tls)
Duration         : ${MIN} minutes
-----------------------------------------
Link TLS :
trojan://${P}@${HOST}:${PORT}?path=%2F${PATH_WS}&security=tls&type=ws#${U}
-----------------------------------------
Saved: http://${HOST}:81/$(basename "$OUT")
Created: $(now)
EOF
  chmod 644 "$OUT" || true
  echo "${U},${P},$(date +%F' '%T),trojan_trial,0" >> "$DB"
  if [[ -f "$OUT" ]]; then cat "$OUT" > "$LAST" || true; fi
  if command -v at >/dev/null 2>&1; then
    echo "sed -i '/^${U},/d' ${DB}; rm -f ${OUT}" | at now + "${MIN}" minutes
  fi
  echo "=> Trojan trial created: ${U}"
  cat "$OUT"
  exit 0
else
  echo "Usage: $0 normal [remarks] [password] [max_login]  OR  $0 trial [minutes]"
  read -p "Mode (1 normal / 2 trial) [1]: " c || true
  if [[ "$c" == "2" ]]; then exec "$0" trial; else exec "$0" normal; fi
fi
TR
chmod +x "$BIN/create_trojan.sh"

# 9) Menu script (1-16) with show-last-after-create
cat > "$BIN/menu" <<'MENU'
#!/bin/bash
NC='\e[0m'; RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; CYAN='\e[36m'; MAGENTA='\e[35m'; BOLD='\e[1m'
BIN=/usr/local/bin; WWW=/var/www/html; LAST=/tmp/last_payload.txt

svc_icon(){ if systemctl is-active --quiet "$1"; then echo -e "${GREEN}● ON${NC}"; else echo -e "${RED}● OFF${NC}"; fi }
count_accounts(){ SSH_COUNT=$(ls "$WWW"/ssh-*.txt 2>/dev/null | wc -l || echo 0); UDP_COUNT=$(ls "$WWW"/udp-*.txt 2>/dev/null | wc -l || echo 0); TROJAN_COUNT=$(ls "$WWW"/trojan-*.txt 2>/dev/null | wc -l || echo 0); PAY_COUNT=$(ls "$WWW"/*.txt 2>/dev/null | wc -l || echo 0); }
print_banner(){ echo -e "${MAGENTA}${BOLD}┌──────────────────────── YHDS VPS PREMIUM ─────────────────────┐${NC}"; echo -e "${MAGENTA}${BOLD}│                    DASHBOARD & MENU 1-16                     │${NC}"; echo -e "${MAGENTA}${BOLD}└──────────────────────────────────────────────────────────────┘${NC}"; }
system_dashboard(){
  count_accounts
  HOSTNAME=$(hostname)
  IP=$(curl -s --max-time 2 ipv4.icanhazip.com || hostname -I | awk '{print $1}')
  RAM=$(free -h | awk '/Mem:/ {print $3 " / " $2}')
  UPTIME=$(uptime -p | sed 's/up //')
  LOAD=$(uptime | awk -F'load average:' '{print $2}')
  echo -e "${CYAN}Host:${NC} $HOSTNAME    ${CYAN}IP:${NC} $IP"
  echo -e "${CYAN}RAM:${NC} $RAM    ${CYAN}Uptime:${NC} $UPTIME    ${CYAN}Load:${NC} $LOAD"
  echo -e "${CYAN}Services:${NC} SSH[$(svc_icon ssh)]  UDP[$(svc_icon udp-custom)]  XRAY[$(svc_icon xray)]  NGINX[$(svc_icon nginx)]"
  echo -e "${CYAN}Accounts:${NC} SSH:$SSH_COUNT  UDP:$UDP_COUNT  TROJAN:$TROJAN_COUNT  PAYLOADS:$PAY_COUNT"
}
show_last_and_pause(){ if [[ -s "$LAST" ]]; then echo -e "${YELLOW}--- LAST PAYLOAD ---${NC}"; sed -n '1,300p' "$LAST" || true; echo -e "${YELLOW}--- END ---${NC}"; read -p "Tekan Enter setelah selesai copy..." _; fi }
print_menu(){
  echo -e "${GREEN}1)${NC} Create SSH (normal)        ${GREEN}2)${NC} Create SSH (trial)"
  echo -e "${GREEN}3)${NC} Create UDP (normal)        ${GREEN}4)${NC} Create UDP (trial)"
  echo -e "${GREEN}5)${NC} Create Trojan (normal)     ${GREEN}6)${NC} Create Trojan (trial)"
  echo -e "${GREEN}7)${NC} Install / Configure Telegram Bot"
  echo -e "${GREEN}8)${NC} Show Running Services      ${GREEN}9)${NC} Restart Services"
  echo -e "${GREEN}10)${NC} Show Last Payload         ${GREEN}11)${NC} List Users"
  echo -e "${GREEN}12)${NC} Toggle SSH                ${GREEN}13)${NC} Toggle UDP-Custom"
  echo -e "${GREEN}14)${NC} Toggle Xray               ${GREEN}15)${NC} Toggle ALL Services"
  echo -e "${GREEN}16)${NC} Exit"
}
while true; do
  clear
  print_banner
  system_dashboard
  print_menu
  read -p "Pilih menu [1-16]: " CH
  case "$CH" in
    1) $BIN/create_ssh.sh normal; show_last_and_pause ;;
    2) $BIN/create_ssh.sh trial; show_last_and_pause ;;
    3) $BIN/create_udp.sh normal; show_last_and_pause ;;
    4) $BIN/create_udp.sh trial; show_last_and_pause ;;
    5) $BIN/create_trojan.sh normal; show_last_and_pause ;;
    6) $BIN/create_trojan.sh trial; show_last_and_pause ;;
    7) $BIN/install_telegram_bot.sh ;;
    8) echo ""; systemctl list-units --type=service --state=running --no-pager --no-legend | sed -n '1,200p'; echo ""; read -p "Tekan Enter...";;
    9) systemctl restart xray nginx ssh dropbear udp-custom 2>/dev/null || true; echo "Restart requested."; sleep 1 ;;
    10) if [[ -s "$LAST" ]]; then sed -n '1,300p' "$LAST"; else echo "(no last payload)"; fi; read -p "Tekan Enter...";;
    11) if [ -f /etc/yhds/users.csv ]; then column -t -s, /etc/yhds/users.csv; else echo "(no users)"; fi; read -p "Tekan Enter...";;
    12) if systemctl is-active --quiet ssh; then systemctl stop ssh || true; else systemctl start ssh || true; fi ;;
    13) if systemctl is-active --quiet udp-custom; then systemctl stop udp-custom || true; else systemctl start udp-custom || true; fi ;;
    14) if systemctl is-active --quiet xray; then systemctl stop xray || true; else systemctl start xray || true; fi ;;
    15) echo "A) Enable All  B) Disable All"; read -p "Choose: " opt; if [[ "${opt,,}" == "a" ]]; then for s in xray trojan-go nginx ssh dropbear udp-custom; do systemctl enable --now $s >/dev/null 2>&1 || true; done; echo "All enabled."; else for s in xray trojan-go nginx ssh dropbear udp-custom; do systemctl stop $s >/dev/null 2>&1 || true; systemctl disable $s >/dev/null 2>&1 || true; done; echo "All disabled."; fi ;;
    16) echo "Exit."; break ;;
    *) echo "Pilihan tidak valid."; sleep 1 ;;
  esac
  echo ""; read -p "Tekan Enter untuk kembali ke menu..." dummy
done
MENU
chmod +x "$BIN/menu"

# 10) Try to install Xray (best-effort) - download release and install
if [[ ! -x "$XRAY_BIN" ]]; then
  echo "Attempting to download and install Xray (best-effort)..."
  tmpdir=$(mktemp -d)
  cd "$tmpdir"
  # common release URL - may fail; script is best-effort and will continue even if fails
  urls=(
    "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
  )
  dlok=0
  for u in "${urls[@]}"; do
    echo "Trying $u ..."
    if curl -L --max-time 60 -o xray.zip "$u" 2>/dev/null; then
      if unzip -o xray.zip >/dev/null 2>&1; then dlok=1; break; fi
    fi
  done
  if [[ $dlok -eq 1 ]] && [[ -f ./xray ]]; then
    mv -f ./xray "$XRAY_BIN"
    chmod +x "$XRAY_BIN"
    echo "Xray binary installed -> $XRAY_BIN"
  else
    echo "Xray download/extract failed (continue without Xray)."
  fi
  rm -rf "$tmpdir"
fi

# 11) Xray systemd service & minimal config (if binary present)
if [[ -x "$XRAY_BIN" ]]; then
  echo "Installing xray systemd service & minimal config (if not exist)..."
  cat > "$XRAY_SYSTEMD" <<'SVC'
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray -c /usr/local/etc/xray/config.json
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVC
  systemctl daemon-reload >/dev/null 2>&1 || true
  # default minimal config (only if config missing)
  if [[ ! -f "$XRAY_CONF" ]]; then
    mkdir -p "$(dirname "$XRAY_CONF")"
    # create self-signed cert for IP
    mkdir -p /etc/ssl/xray || true
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/ssl/xray/trojan.key -out /etc/ssl/xray/trojan.crt -subj "/CN=${IP_PUB}" >/dev/null 2>&1 || true

    cat > "$XRAY_CONF" <<'JSON'
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "initial-password",
            "flow": ""
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "wsSettings": {
          "path": "/trojan-ws",
          "headers": {}
        },
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/xray/trojan.crt",
              "keyFile": "/etc/ssl/xray/trojan.key"
            }
          ]
        }
      },
      "tag": "trojan-ws-in"
    }
  ],
  "outbounds": [
    {"protocol": "freedom","settings":{}}
  ]
}
JSON
  fi

  mkdir -p /var/log/xray
  chown -R root:root /var/log/xray 2>/dev/null || true
  systemctl enable --now xray >/dev/null 2>&1 || systemctl start xray >/dev/null 2>&1 || true
  sleep 1
  echo "Xray status: $(systemctl is-active xray 2>/dev/null || echo inactive)"
fi

# 12) Final perms & finish
chmod -R 755 "$BIN" 2>/dev/null || true
chown -R root:root "$BIN" 2>/dev/null || true
chown -R www-data:www-data "$WWW" 2>/dev/null || true

echo ""
echo "INSTALL COMPLETE."
echo "Files created:"
echo " - Menu: /usr/local/bin/menu"
echo " - Create helpers: /usr/local/bin/create_ssh.sh, create_udp.sh, create_trojan.sh"
echo " - Web payload dir: /var/www/html (nginx on port 81)"
echo " - Xray: $XRAY_BIN (status: $( [[ -x $XRAY_BIN ]] && systemctl is-active xray || echo 'not-installed' ))"
echo ""
echo "Run 'menu' to start the dashboard."
echo "If Xray is not installed by this script, install Xray manually and ensure /usr/local/etc/xray/config.json exists, then 'systemctl enable --now xray'."
echo "Backups saved to $BACKUP_DIR"
