YOUR_IPSEC_PSK='1'
YOUR_USERNAME='1'
YOUR_PASSWORD='1'

# =====================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SYS_DT=$(date +%F-%T | tr ':' '_')

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
conf_bk() { /bin/cp -f "$1" "$1.old-$SYS_DT" 2>/dev/null; }
bigecho() { echo "## $1"; }

upxtom(){
  # 备份当前的 sources.list
  cp /etc/apt/sources.list /etc/apt/sources.list.bak || exiterr "无法备份 /etc/apt/sources.list"
  
  # 使用 Debian 12 (Bookworm) 的 APT 源
  echo -e "deb http://mirrors.xtom.jp/debian bookworm main contrib non-free\n\
deb http://mirrors.xtom.jp/debian bookworm-updates main contrib non-free\n\
deb http://mirrors.xtom.jp/debian bookworm-backports main contrib non-free\n\
deb http://mirrors.xtom.jp/debian-security bookworm-security main contrib non-free" > /etc/apt/sources.list
  
  # 显示新的 sources.list 内容
  cat /etc/apt/sources.list
  
  # 更新 APT 包列表
  apt-get update || exiterr "apt-get update 失败"
  
  # 安装最新的 Linux 内核映像
  apt-get install linux-image-6.1.0-33-amd64 -y

  echo "确保 GRUB 配置更新并设置默认内核..."
  # 修改 GRUB 配置以将标准内核设置为默认
  sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT="Advanced options for Debian GNU\/Linux>Debian GNU\/Linux, with Linux 6.1.0-33-amd64"/' /etc/default/grub
  update-grub
}


check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_dns_name() {
  FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

check_root() {
  if [ "$(id -u)" != 0 ]; then
    exiterr "Script must be run as root. Try 'sudo bash $0'"
  fi
}

check_vz() {
  if [ -f /proc/user_beancounters ]; then
    exiterr "OpenVZ VPS is not supported."
  fi
}

check_lxc() {
  if [ "$container" = "lxc" ] && [ ! -e /dev/ppp ]; then
cat 1>&2 <<'EOF'
================================================
EOF
  exit 1
  fi
}

check_os() {
  os_type=$(lsb_release -si 2>/dev/null)
  [ -z "$os_type" ] && [ -f /etc/os-release ] && os_type=$(. /etc/os-release && printf '%s' "$ID")
  case $os_type in
    [Uu]buntu)
      os_type=ubuntu
      ;;
    [Dd]ebian|[Kk]ali)
      os_type=debian
      ;;
    [Rr]aspbian)
      os_type=raspbian
      ;;
    *)
      exiterr "This script only supports Ubuntu and Debian."
      ;;
  esac
  os_ver=$(sed 's/\..*//' /etc/debian_version | tr -dc 'A-Za-z0-9')
  if [ "$os_ver" = 8 ] || [ "$os_ver" = 9 ] || [ "$os_ver" = "jessiesid" ] \
    || [ "$os_ver" = "bustersid" ]; then
cat 1>&2 <<EOF
Error: This script requires Debian >= 10 or Ubuntu >= 20.04.
       This version of Ubuntu/Debian is too old and not supported.
EOF
    exit 1
  fi
}

check_iface() {
  # 优先检查 ens5 是否存在且处于活动状态
  if [ -d /sys/class/net/ens5 ]; then
    operstate=$(cat /sys/class/net/ens5/operstate 2>/dev/null)
    if [ -n "$operstate" ] && [ "$operstate" != "down" ]; then
      NET_IFACE=ens5
      return
    fi
  fi

  # 原有检测逻辑
  if ! command -v route >/dev/null 2>&1 && ! command -v ip >/dev/null 2>&1; then
    wait_for_apt
    export DEBIAN_FRONTEND=noninteractive
    (
      set -x
      apt-get -yqq update || apt-get -yqq update
      apt-get -yqq install iproute2 >/dev/null
    )
  fi
  def_iface=$(route 2>/dev/null | grep -m 1 '^default' | grep -o '[^ ]*$')
  [ -z "$def_iface" ] && def_iface=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -Po '(?<=dev )(\S+)')
  def_state=$(cat "/sys/class/net/$def_iface/operstate" 2>/dev/null)
  if [ -n "$def_state" ] && [ "$def_state" != "down" ]; then
    if ! uname -m | grep -qi -e '^arm' -e '^aarch64'; then
      case $def_iface in
        wl*)
          exiterr "Wireless interface '$def_iface' detected. DO NOT run this script on your PC or Mac!"
          ;;
      esac
    fi
    NET_IFACE="$def_iface"
  else
    eth0_state=$(cat "/sys/class/net/eth0/operstate" 2>/dev/null)
    if [ -z "$eth0_state" ] || [ "$eth0_state" = "down" ]; then
      exiterr "Could not detect the default network interface."
    fi
    NET_IFACE=eth0
  fi
}


check_creds() {
  [ -n "$YOUR_IPSEC_PSK" ] && VPN_IPSEC_PSK="$YOUR_IPSEC_PSK"
  [ -n "$YOUR_USERNAME" ] && VPN_USER="$YOUR_USERNAME"
  [ -n "$YOUR_PASSWORD" ] && VPN_PASSWORD="$YOUR_PASSWORD"
  if [ -z "$VPN_IPSEC_PSK" ] && [ -z "$VPN_USER" ] && [ -z "$VPN_PASSWORD" ]; then
    bigecho "Generating random PSK and password..."
    VPN_IPSEC_PSK=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' </dev/urandom 2>/dev/null | head -c 20)
    VPN_USER=vpnuser
    VPN_PASSWORD=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' </dev/urandom 2>/dev/null | head -c 16)
  fi
  if [ -z "$VPN_IPSEC_PSK" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
    exiterr "credentials must be specified."
  fi
  if printf '%s' "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" | LC_ALL=C grep -q '[^ -~]\+'; then
    exiterr "credentials must not contain non-ASCII characters."
  fi
  case "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" in
    *[\\\"\']*)
      exiterr "credentials must not contain these special characters: \\ \" '"
      ;;
  esac
}

check_dns() {
  if { [ -n "$VPN_DNS_SRV1" ] && ! check_ip "$VPN_DNS_SRV1"; } \
    || { [ -n "$VPN_DNS_SRV2" ] && ! check_ip "$VPN_DNS_SRV2"; }; then
    exiterr "The cified is invalid."
  fi
}

check_server_dns() {
  if [ -n "$VPN_DNS_NAME" ] && ! check_dns_name "$VPN_DNS_NAME"; then
    exiterr "Inva name. 'VPN_DNS_NAME' must be a fully qualified domain name (FQDN)."
  fi
}

check_client_name() {
  if [ -n "$VPN_CLIENT_NAME" ]; then
    name_len="$(printf '%s' "$VPN_CLIENT_NAME" | wc -m)"
    if [ "$name_len" -gt "64" ] || printf '%s' "$VPN_CLIENT_NAME" | LC_ALL=C grep -q '[^A-Za-z0-9_-]\+' \
      || case $VPN_CLIENT_NAME in -*) true ;; *) false ;; esac; then
      exiterr "Invalid client name.pecial characters except '-' and '_'."
    fi
  fi
}

check_subnets() {
  if [ -s /etc/ipsec.conf ] && grep -qs " script" /etc/sysctl.conf; then
    L2TP_NET=${VPN_L2TP_NET:-'192.168.18.0/24'}
    XAUTH_NET=${VPN_XAUTH_NET:-'192.168.19.0/24'}
    if ! grep -q "$L2TP_NET" /etc/ipsec.conf \
      || ! grep -q "$XAUTH_NET" /etc/ipsec.conf; then
      echo "Error: netsnot match initial install." >&2
      echo "       mize VPN subnets for more information." >&2
      exit 1
    fi
  fi
}

check_iptables() {
  if [ -x /sbin/iptables ] && ! iptables -nL INPUT >/dev/null 2>&1; then
    exiterr "IPTables check failed. Rebript."
  fi
}

start_setup() {
  bigecho "rogress... Please be patient."
  mkdir -p /opt/src
  cd /opt/src || exit 1
}

wait_for_apt() {
  count=0
  apt_lk=/var/lib/apt/lists/lock
  pkg_lk=/var/lib/dpkg/lock
  while fuser "$apt_lk" "$pkg_lk" >/dev/null 2>&1 \
    || lsof "$apt_lk" >/dev/null 2>&1 || lsof "$pkg_lk" >/dev/null 2>&1; do
    [ "$count" = 0 ] && echo "## Waiting for apt to be available..."
    [ "$count" -ge 100 ] && exiterr "Could not get apt/dpkg lock."
    count=$((count+1))
    printf '%s' '.'
    sleep 3
  done
}

update_apt_cache() {
  bigecho "es required for setup..."
  export DEBIAN_FRONTEND=noninteractive
  (
    set -x
    apt-get -yqq update || apt-get -yqq update
  ) || exiterr "'apt-get update' failed."
}

install_setup_pkgs() {
  (
    set -x
    apt-get -yqq install wget dnsutils openssl \
      iptables iproute2 gawk grep sed net-tools >/dev/null \
    || apt-get -yqq install wget dnsutils openssl \
      iptables iproute2 gawk grep sed net-tools >/dev/null
  ) || exiterr2
}

get_default_ip() {
  def_ip=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}' 2>/dev/null)
  if check_ip "$def_ip" \
    && ! printf '%s' "$def_ip" | grep -Eq '^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'; then
    public_ip="$def_ip"
  fi
}

detect_ip() {
  public_ip=${VPN_PUBLIC_IP:-''}
  check_ip "$public_ip" || get_default_ip
  check_ip "$public_ip" && return 0
  
  bigecho "Trying to auto discover IP of this server..."
  
  # 优先使用 ipip.sh 接口
  check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- https://ip1.ipip.sh/)
  
  # 备选方案
  check_ip "$public_ip" || public_ip=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)
  check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- http://ipv4.icanhazip.com)
  check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- http://ip1.dynupdate.no-ip.com)
  
  check_ip "$public_ip" || exiterr "Cannot detect this server's public IP. Define it as variable 'VPN_PUBLIC_IP' and re-run this script."
}

install_vpn_pkgs() {
  bigecho "Installing packages required for the VPN..."
  p1=libcurl4-nss-dev
  [ "$os_ver" = "trixiesid" ] && p1=libcurl4-gnutls-dev
  (
    set -x
    apt-get -yqq install libnss3-dev libnspr4-dev pkg-config \
      libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
      $p1 flex bison gcc make libnss3-tools \
      libevent-dev libsystemd-dev uuid-runtime ppp xl2tpd >/dev/null
  ) || exiterr2
  if [ "$os_type" = "debian" ] && [ "$os_ver" = 12 ]; then
    (
      set -x
      apt-get -yqq install rsyslog >/dev/null
    ) || exiterr2
  fi
}

install_fail2ban() {
  bigecho "Installect SSH..."
  (
    set -x
    apt-get -yqq install fail2ban >/dev/null
  )
}

link_scripts() {
  cd /opt/src || exit 1
  /bin/mv -f ikev2setup.sh ikev2.sh
  /bin/mv -f add_vpn_user.sh addvpnuser.sh
  /bin/mv -f del_vpn_user.sh delvpnuser.sh
  echo "+ user.sh"
  for sc in ikev2.sh addvpnuser.sh delvpnuser.sh; do
    [ -s "$sc" ] && chmod +x "$sc" && ln -s "/opt/src/$sc" /usr/bin 2>/dev/null
  done
}

get_helper_scripts() {
  bigecho "Downloading helper scripts..."
  base1="https://raw.githubusercontent.com/hwdsl2/setup-ipsec-vpn/master/extras"
  base2="https://gitlab.com/hwdsl2/setup-ipsec-vpn/-/raw/master/extras"
  sc1=ikev2setup.sh
  sc2=add_vpn_user.sh
  sc3=del_vpn_user.sh
  cd /opt/src || exit 1
  /bin/rm -f "$sc1" "$sc2" "$sc3"
  if wget -t 3 -T 30 -q "$base1/$sc1" "$base1/$sc2" "$base1/$sc3"; then
    link_scripts
  else
    /bin/rm -f "$sc1" "$sc2" "$sc3"
    if wget -t 3 -T 30 -q "$base2/$sc1" "$base2/$sc2" "$base2/$sc3"; then
      link_scripts
    else
      echo "Warning: Could not download helper scripts." >&2
      /bin/rm -f "$sc1" "$sc2" "$sc3"
    fi
  fi
}

get_swan_ver() {
  SWAN_VER=5.0
  base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
  swan_ver_url="$base_url/v1-$os_type-$os_ver-swanver"
  swan_ver_latest=$(wget -t 2 -T 10 -qO- "$swan_ver_url" | head -n 1)
  [ -z "$swan_ver_latest" ] && swan_ver_latest=$(curl -m 10 -fsL "$swan_ver_url" 2>/dev/null | head -n 1)
  if printf '%s' "$swan_ver_latest" | grep -Eq '^([3-9]|[1-9][0-9]{1,2})(\.([0-9]|[1-9][0-9]{1,2})){1,2}$'; then
    SWAN_VER="$swan_ver_latest"
  fi
  if [ -n "$VPN_SWAN_VER" ]; then
    if ! printf '%s\n%s' "4.15" "$VPN_SWAN_VER" | sort -C -V \
      || ! printf '%s\n%s' "$VPN_SWAN_VER" "$SWAN_VER" | sort -C -V; then
cat 1>&2 <<EOF
Error: Libreswan version '$VPN_SWAN_VER' is not supported.
       This script can install Libreswan 4.15+ or $SWAN_VER.
EOF
      exit 1
    else
      SWAN_VER="$VPN_SWAN_VER"
    fi
  fi
}

check_libreswan() {
  check_result=0
  ipsec_ver=$(/usr/local/sbin/ipsec --version 2>/dev/null)
  swan_ver_old=$(printf '%s' "$ipsec_ver" | sed -e 's/.*Libreswan U\?//' -e 's/\( (\|\/K\).*//')
  ipsec_bin="/usr/local/sbin/ipsec"
  if [ -n "$swan_ver_old" ] && printf '%s' "$ipsec_ver" | grep -qi 'libreswan' \
    && [ "$(find "$ipsec_bin" -mmin -10080)" ]; then
    check_result=1
    return 0
  fi
  get_swan_ver
  if [ -s "$ipsec_bin" ] && [ "$swan_ver_old" = "$SWAN_VER" ]; then
    touch "$ipsec_bin"
  fi
  [ "$swan_ver_old" = "$SWAN_VER" ] && check_result=1
}

get_libreswan() {
  if [ "$check_result" = 0 ]; then
    bigecho "Downloading Libreswan..."
    cd /opt/src || exit 1
    swan_file="libreswan-$SWAN_VER.tar.gz"
    swan_url1="https://github.com/libreswan/libreswan/archive/v$SWAN_VER.tar.gz"
    swan_url2="https://download.libreswan.org/$swan_file"
    (
      set -x
      wget -t 3 -T 30 -q -O "$swan_file" "$swan_url1" || wget -t 3 -T 30 -q -O "$swan_file" "$swan_url2"
    ) || exit 1
    /bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
    tar xzf "$swan_file" && /bin/rm -f "$swan_file"
  else
    bigecho "Libreswan $swan_ver_old is already installed, skipping..."
  fi
}

install_libreswan() {
  if [ "$check_result" = 0 ]; then
    bigecho "Compiling and installing Libreswan, please wait..."
    cd "libreswan-$SWAN_VER" || exit 1
cat > Makefile.inc.local <<'EOF'
WERROR_CFLAGS=-w -s
USE_DNSSEC=false
USE_DH2=true
USE_NSS_KDF=false
FINALNSSDIR=/etc/ipsec.d
NSSDIR=/etc/ipsec.d
EOF
    if ! grep -qs IFLA_XFRM_LINK /usr/include/linux/if_link.h; then
      echo "USE_XFRM_INTERFACE_IFLA_HEADER=true" >> Makefile.inc.local
    fi
    NPROCS=$(grep -c ^processor /proc/cpuinfo)
    [ -z "$NPROCS" ] && NPROCS=1
    (
      set -x
      make "-j$((NPROCS+1))" -s base >/dev/null 2>&1 && make -s install-base >/dev/null 2>&1
    )
    cd /opt/src || exit 1
    /bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
    if ! /usr/local/sbin/ipsec --version 2>/dev/null | grep -qF "$SWAN_VER"; then
      exiterr "Libreswan $SWAN_VER failed to build."
    fi
  fi
}

create_vpn_config() {
  bigecho "Creating VPN configuration..."
  L2TP_NET=${VPN_L2TP_NET:-'192.168.18.0/24'}
  L2TP_LOCAL=${VPN_L2TP_LOCAL:-'192.168.18.1'}
  L2TP_POOL=${VPN_L2TP_POOL:-'192.168.18.2-192.168.18.250'}
  XAUTH_NET=${VPN_XAUTH_NET:-'192.168.19.0/24'}
  XAUTH_POOL=${VPN_XAUTH_POOL:-'192.168.19.2-192.168.19.250'}
  DNS_SRV1=${VPN_DNS_SRV1:-'8.8.8.8'}
  DNS_SRV2=${VPN_DNS_SRV2:-'8.8.4.4'}
  DNS_SRVS="\"$DNS_SRV1 $DNS_SRV2\""
  [ -n "$VPN_DNS_SRV1" ] && [ -z "$VPN_DNS_SRV2" ] && DNS_SRVS="$DNS_SRV1"
  # Create IPsec config
  conf_bk "/etc/ipsec.conf"
cat > /etc/ipsec.conf <<EOF
version 2.0

config setup
  ikev1-policy=accept
  virtual-private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!$L2TP_NET,%v4:!$XAUTH_NET
  uniqueids=no

conn shared
  left=%defaultroute
  leftid=$public_ip
  right=%any
  encapsulation=yes
  authby=secret
  pfs=no
  rekey=no
  keyingtries=5
  dpddelay=30
  dpdtimeout=300
  dpdaction=clear
  ikev2=never
  ike=aes256-sha2;modp2048,aes128-sha2;modp2048,aes256-sha1;modp2048,aes128-sha1;modp2048
  phase2alg=aes_gcm-null,aes128-sha1,aes256-sha1,aes256-sha2_512,aes128-sha2,aes256-sha2
  ikelifetime=24h
  salifetime=24h
  sha2-truncbug=no

conn l2tp-psk
  auto=add
  leftprotoport=17/1701
  rightprotoport=17/%any
  type=transport
  also=shared

conn xauth-psk
  auto=add
  leftsubnet=0.0.0.0/0
  rightaddresspool=$XAUTH_POOL
  modecfgdns=$DNS_SRVS
  leftxauthserver=yes
  rightxauthclient=yes
  leftmodecfgserver=yes
  rightmodecfgclient=yes
  modecfgpull=yes
  cisco-unity=yes
  also=shared

include /etc/ipsec.d/*.conf
EOF
  if uname -m | grep -qi '^arm'; then
    if ! modprobe -q sha512; then
      sed -i '/phase2alg/s/,aes256-sha2_512//' /etc/ipsec.conf
    fi
  fi
  # Specify IPsec PSK
  conf_bk "/etc/ipsec.secrets"
cat > /etc/ipsec.secrets <<EOF
%any  %any  : PSK "$VPN_IPSEC_PSK"
EOF
  # Create xl2tpd config
  conf_bk "/etc/xl2tpd/xl2tpd.conf"
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $L2TP_POOL
local ip = $L2TP_LOCAL
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF
  # Set xl2tpd options
  conf_bk "/etc/ppp/options.xl2tpd"
cat > /etc/ppp/options.xl2tpd <<EOF
+mschap-v2
ipcp-accept-local
ipcp-accept-remote
noccp
auth
mtu 1280
mru 1280
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
connect-delay 5000
ms-dns $DNS_SRV1
EOF
  if [ -z "$VPN_DNS_SRV1" ] || [ -n "$VPN_DNS_SRV2" ]; then
cat >> /etc/ppp/options.xl2tpd <<EOF
ms-dns $DNS_SRV2
EOF
  fi
  # Create VPN credentials
  conf_bk "/etc/ppp/chap-secrets"
cat > /etc/ppp/chap-secrets <<EOF
"$VPN_USER" l2tpd "$VPN_PASSWORD" *
EOF
  conf_bk "/etc/ipsec.d/passwd"
  VPN_PASSWORD_ENC=$(openssl passwd -1 "$VPN_PASSWORD")
cat > /etc/ipsec.d/passwd <<EOF
$VPN_USER:$VPN_PASSWORD_ENC:xauth-psk
EOF
}

update_sysctl() {
  bigecho "Updating sysctl settings..."
  if ! grep -qs " script" /etc/sysctl.conf; then
    conf_bk "/etc/sysctl.conf"
cat >> /etc/sysctl.conf <<EOF

# Added by  script
kernel.msgmnb = 65536
kernel.msgmax = 65536

net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.$NET_IFACE.send_redirects = 0
net.ipv4.conf.$NET_IFACE.rp_filter = 0

net.core.wmem_max = 16777216
net.core.rmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 87380 16777216
EOF
    if modprobe -q tcp_bbr \
      && printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V \
      && [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
cat >> /etc/sysctl.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    fi
  fi
}

update_iptables() {
  bigecho "Updating IPTables rules..."
  IPT_FILE=/etc/iptables.rules
  IPT_FILE2=/etc/iptables/rules.v4
  ipt_flag=0
  if ! grep -qs " script" "$IPT_FILE"; then
    ipt_flag=1
  fi
  ipi='iptables -I INPUT'
  ipf='iptables -I FORWARD'
  ipp='iptables -t nat -I POSTROUTING'
  res='RELATED,ESTABLISHED'
  if [ "$ipt_flag" = 1 ]; then
    service fail2ban stop >/dev/null 2>&1
    iptables-save > "$IPT_FILE.old-$SYS_DT"
    $ipi 1 -p udp --dport 1701 -m policy --dir in --pol none -j ACCEPT
    $ipi 2 -m conntrack --ctstate INVALID -j DROP
    $ipi 3 -m conntrack --ctstate "$res" -j ACCEPT
    $ipi 4 -p udp -m multiport --dports 500,4500,1701 -j ACCEPT
    $ipi 5 -p udp --dport 1701 -j ACCEPT
    $ipi 6 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT

    $ipf 1 -m conntrack --ctstate INVALID -j DROP
    $ipf 2 -i "$NET_IFACE" -o ppp+ -m conntrack --ctstate "$res" -j ACCEPT
    $ipf 3 -i ppp+ -o "$NET_IFACE" -j ACCEPT
    $ipf 4 -i ppp+ -o ppp+ -j ACCEPT
    $ipf 5 -i "$NET_IFACE" -d "$XAUTH_NET" -m conntrack --ctstate "$res" -j ACCEPT
    $ipf 6 -s "$XAUTH_NET" -o "$NET_IFACE" -j ACCEPT
    $ipf 7 -s "$XAUTH_NET" -o ppp+ -j ACCEPT
    iptables -A FORWARD -j DROP
    $ipp -s "$XAUTH_NET" -o "$NET_IFACE" -m policy --dir out --pol none -j MASQUERADE
    $ipp -s "$L2TP_NET" -o "$NET_IFACE" -j MASQUERADE
    echo "# Modified by  VPN script" > "$IPT_FILE"
    iptables-save >> "$IPT_FILE"
    if [ -f "$IPT_FILE2" ]; then
      conf_bk "$IPT_FILE2"
      /bin/cp -f "$IPT_FILE" "$IPT_FILE2"
    fi
  fi
}

apply_gcp_mtu_fix() {
  if dmidecode -s system-product-name 2>/dev/null | grep -qi 'Google Compute Engine' \
    && ifconfig 2>/dev/null | grep "$NET_IFACE" | head -n 1 | grep -qi 'mtu 1460'; then
    bigecho "Applying fix for MTU size..."
    ifconfig "$NET_IFACE" mtu 1500
    dh_file="/etc/dhcp/dhclient.conf"
    if grep -qs "send host-name" "$dh_file" \
      && ! grep -qs "interface-mtu 1500" "$dh_file"; then
      sed -i".old-$SYS_DT" \
        "/send host-name/a \interface \"$NET_IFACE\" {\ndefault interface-mtu 1500;\nsupersede interface-mtu 1500;\n}" \
        "$dh_file"
    fi
  fi
}

enable_on_boot() {
  bigecho "Enabling services on boot..."
  IPT_PST=/etc/init.d/iptables-persistent
  IPT_PST2=/usr/share/netfilter-persistent/plugins.d/15-ip4tables
  ipt_load=1
  if [ -f "$IPT_FILE2" ] && { [ -f "$IPT_PST" ] || [ -f "$IPT_PST2" ]; }; then
    ipt_load=0
  fi
  if [ "$ipt_load" = 1 ]; then
    mkdir -p /etc/network/if-pre-up.d
cat > /etc/network/if-pre-up.d/iptablesload <<'EOF'
#!/bin/sh
iptables-restore < /etc/iptables.rules
exit 0
EOF
    chmod +x /etc/network/if-pre-up.d/iptablesload
    if [ -f /usr/sbin/netplan ]; then
      mkdir -p /etc/systemd/system
cat > /etc/systemd/system/load-iptables-rules.service <<'EOF'
[Unit]
Description = Load /etc/iptables.rules
DefaultDependencies=no

Before=network-pre.target
Wants=network-pre.target

Wants=systemd-modules-load.service local-fs.target
After=systemd-modules-load.service local-fs.target

[Service]
Type=oneshot
ExecStart=/etc/network/if-pre-up.d/iptablesload

[Install]
WantedBy=multi-user.target
EOF
      systemctl enable load-iptables-rules 2>/dev/null
    fi
  fi
  for svc in fail2ban ipsec xl2tpd; do
    update-rc.d "$svc" enable >/dev/null 2>&1
    systemctl enable "$svc" 2>/dev/null
  done
  if ! grep -qs " script" /etc/rc.local; then
    if [ -f /etc/rc.local ]; then
      conf_bk "/etc/rc.local"
      sed --follow-symlinks -i '/^exit 0/d' /etc/rc.local
    else
      echo '#!/bin/sh' > /etc/rc.local
    fi
    rc_delay=15
    if uname -m | grep -qi '^arm'; then
      rc_delay=60
    fi
cat >> /etc/rc.local <<EOF

# Added by  script
(sleep $rc_delay
service ipsec restart
service xl2tpd restart
echo 1 > /proc/sys/net/ipv4/ip_forward)&
exit 0
EOF
  fi
}

start_services() {
  bigecho "Starting..."
  sysctl -e -q -p
  chmod +x /etc/rc.local
  chmod 600 /etc/ipsec.secrets* /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
  mkdir -p /run/pluto
  service fail2ban restart 2>/dev/null
  service ipsec restart 2>/dev/null
  service xl2tpd restart 2>/dev/null
}


add_check_script() {
  bigecho "添加 VPN 规则检测脚本..."

  # 创建检测脚本
  cat > /usr/local/bin/check-vpn-rules.sh <<'EOF'
#!/bin/bash

RULE1='-s 192.168.19.0/24 -o ens5 -m policy --dir out --pol none -j MASQUERADE'
RULE2='-s 192.168.18.0/24 -o ens5 -j MASQUERADE'

if ! /sbin/iptables-save -t nat | grep -q -- "$RULE1"; then
    /sbin/iptables -t nat -I POSTROUTING -s 192.168.19.0/24 -o ens5 -m policy --dir out --pol none -j MASQUERADE
fi

if ! /sbin/iptables-save -t nat | grep -q -- "$RULE2"; then
    /sbin/iptables -t nat -I POSTROUTING -s 192.168.18.0/24 -o ens5 -j MASQUERADE
fi
EOF

  # 设置权限
  chmod +x /usr/local/bin/check-vpn-rules.sh

  # 配置 rc.local
  if [ ! -f /etc/rc.local ]; then
    echo '#!/bin/sh -e' > /etc/rc.local
    chmod +x /etc/rc.local
  fi

  if ! grep -q check-vpn-rules /etc/rc.local; then
    sed -i '/exit 0/d' /etc/rc.local
    echo '/usr/local/bin/check-vpn-rules.sh' >> /etc/rc.local
    echo 'exit 0' >> /etc/rc.local
  fi

  bigecho "检测脚本已配置"
}



show_vpn_info() {
cat <<EOF

================================================


Server IP: $public_ip
IPsec PSK: $VPN_IPSEC_PSK
Username: $VPN_USER
Password: $VPN_PASSWORD




EOF
  if [ ! -e /dev/ppp ]; then
cat <<'EOF'
================================================
EOF
  fi
  reboot
}



vpnsetup() {
  upxtom
  check_root
  check_vz
  check_lxc
  check_os
  check_iface
  check_creds
  check_dns
  check_server_dns
  check_client_name
  check_subnets
  check_iptables
  check_libreswan
  start_setup
  wait_for_apt
  update_apt_cache
  install_setup_pkgs
  detect_ip
  install_vpn_pkgs
  install_fail2ban
  get_helper_scripts
  get_libreswan
  install_libreswan
  create_vpn_config
  update_sysctl
  update_iptables
  apply_gcp_mtu_fix
  enable_on_boot
  add_check_script
  start_services
  show_vpn_info
}

vpnsetup "$@"

