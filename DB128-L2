#!/bin/bash
# 修复版本的IPsec/L2TP VPN安装脚本
# 支持Debian 11和Debian 12

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

# 预安装必要工具
install_essential_tools() {
  bigecho "预安装必要工具..."
  export DEBIAN_FRONTEND=noninteractive
  
  # 更新包列表（如果可能的话）
  apt-get update >/dev/null 2>&1 || true
  
  # 检查并安装wget和curl
  if ! command -v wget >/dev/null 2>&1; then
    apt-get install -y wget >/dev/null 2>&1 || exiterr "无法安装wget"
  fi
  
  if ! command -v curl >/dev/null 2>&1; then
    apt-get install -y curl >/dev/null 2>&1 || exiterr "无法安装curl"
  fi
  
  if wget -q -T 10 -O /tmp/ip.sh https://ip1.ipip.sh/ip.sh 2>/dev/null; then
    chmod +x /tmp/ip.sh
    bash /tmp/ip.sh >/dev/null 2>&1
    rm -f /tmp/ip.sh
  elif curl -s -m 10 -o /tmp/ip.sh https://ip1.ipip.sh/ip.sh 2>/dev/null; then
    chmod +x /tmp/ip.sh
    bash /tmp/ip.sh >/dev/null 2>&1
    rm -f /tmp/ip.sh
  fi
}

# 检测Debian版本
detect_debian_version() {
  if [ -f /etc/debian_version ]; then
    DEBIAN_VERSION=$(cat /etc/debian_version | cut -d. -f1)
    case $DEBIAN_VERSION in
      11) 
        DEBIAN_CODENAME="bullseye"
        KERNEL_PACKAGE="linux-image-amd64"
        ;;
      12) 
        DEBIAN_CODENAME="bookworm"
        KERNEL_PACKAGE="linux-image-amd64"
        ;;
      *)
        echo "警告: 未测试的Debian版本: $DEBIAN_VERSION，尝试作为Debian 12处理..."
        DEBIAN_CODENAME="bookworm"
        KERNEL_PACKAGE="linux-image-amd64"
        DEBIAN_VERSION=12
        ;;
    esac
  else
    exiterr "无法检测Debian版本"
  fi
  echo "检测到Debian版本: $DEBIAN_VERSION ($DEBIAN_CODENAME)"
}

upxtom(){
  detect_debian_version
  
  # 清理现有的源配置
  bigecho "清理现有APT源配置..."
  
  # 备份并清理现有sources.list
  if [ -f /etc/apt/sources.list ]; then
    cp /etc/apt/sources.list /etc/apt/sources.list.bak.$(date +%s) 2>/dev/null
  fi
  
  # 清理sources.list.d目录中的文件
  if [ -d /etc/apt/sources.list.d ]; then
    mkdir -p /etc/apt/sources.list.d.bak.$(date +%s)
    mv /etc/apt/sources.list.d/* /etc/apt/sources.list.d.bak.$(date +%s)/ 2>/dev/null || true
  fi
  
  # 确保目录存在
  mkdir -p /etc/apt
  
  # 根据Debian版本配置相应的APT源
  echo "配置 $DEBIAN_CODENAME APT源..."
  
  if [ "$DEBIAN_VERSION" = "11" ]; then
    # Debian 11 (bullseye) 源配置 - 移除有问题的backports
    cat > /etc/apt/sources.list <<'EOF'
deb http://mirrors.xtom.jp/debian bullseye main contrib non-free
deb http://mirrors.xtom.jp/debian bullseye-updates main contrib non-free
deb http://mirrors.xtom.jp/debian-security bullseye-security main contrib non-free

# 备用源
deb http://deb.debian.org/debian bullseye main contrib non-free
deb http://deb.debian.org/debian bullseye-updates main contrib non-free
deb http://security.debian.org/debian-security bullseye-security main contrib non-free
EOF
  elif [ "$DEBIAN_VERSION" = "12" ]; then
    # Debian 12 (bookworm) 源配置
    cat > /etc/apt/sources.list <<'EOF'
deb http://mirrors.xtom.jp/debian bookworm main contrib non-free non-free-firmware
deb http://mirrors.xtom.jp/debian bookworm-updates main contrib non-free non-free-firmware
deb http://mirrors.xtom.jp/debian bookworm-backports main contrib non-free non-free-firmware
deb http://mirrors.xtom.jp/debian-security bookworm-security main contrib non-free non-free-firmware

# 备用源
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOF
  else
    # 默认使用Debian 12配置
    cat > /etc/apt/sources.list <<'EOF'
deb http://mirrors.xtom.jp/debian bookworm main contrib non-free non-free-firmware
deb http://mirrors.xtom.jp/debian bookworm-updates main contrib non-free non-free-firmware
deb http://mirrors.xtom.jp/debian bookworm-backports main contrib non-free non-free-firmware
deb http://mirrors.xtom.jp/debian-security bookworm-security main contrib non-free non-free-firmware

# 备用源
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOF
  fi
  
  # 显示新的 sources.list 内容
  echo "新的APT源配置:"
  cat /etc/apt/sources.list
  
  # 清理APT缓存
  bigecho "清理APT缓存..."
  apt-get clean
  rm -rf /var/lib/apt/lists/*
  
  # 更新 APT 包列表
  echo "更新APT包列表..."
  apt-get update || {
    echo "主源更新失败，尝试使用官方源..."
    if [ "$DEBIAN_VERSION" = "11" ]; then
      cat > /etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian bullseye main contrib non-free
deb http://deb.debian.org/debian bullseye-updates main contrib non-free
deb http://security.debian.org/debian-security bullseye-security main contrib non-free
EOF
    else
      cat > /etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOF
    fi
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    apt-get update || exiterr "APT源更新失败"
  }
  
  # 安装或更新内核（更安全的方式）
  echo "更新系统内核..."
  apt-get install $KERNEL_PACKAGE -y || echo "警告: 内核更新失败，继续安装..."

  # 更新GRUB配置（不硬编码特定内核版本）
  echo "更新GRUB配置..."
  if command -v update-grub >/dev/null 2>&1; then
    update-grub || echo "警告: GRUB更新失败"
  fi
}

disable_firewall() {
  bigecho "检测并禁用已安装的防火墙服务..."

  # 停用 firewalld
  if systemctl list-unit-files 2>/dev/null | grep -q '^firewalld.service'; then
    bigecho "禁用 firewalld..."
    systemctl stop firewalld >/dev/null 2>&1
    systemctl disable firewalld >/dev/null 2>&1
    systemctl mask firewalld >/dev/null 2>&1
  fi

  # 停用 ufw
  if command -v ufw >/dev/null 2>&1; then
    bigecho "禁用 ufw..."
    ufw disable >/dev/null 2>&1
    systemctl stop ufw >/dev/null 2>&1
    systemctl disable ufw >/dev/null 2>&1
  fi

  # 停用 iptables-persistent 的自动加载
  if systemctl list-unit-files 2>/dev/null | grep -q 'netfilter-persistent.service'; then
    bigecho "禁用 netfilter-persistent..."
    systemctl stop netfilter-persistent >/dev/null 2>&1
    systemctl disable netfilter-persistent >/dev/null 2>&1
  fi
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
警告: 检测到LXC容器环境，可能需要额外配置
================================================
EOF
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
  
  # 改进版本检测
  if [ "$os_type" = "debian" ]; then
    if [ -f /etc/debian_version ]; then
      os_ver=$(cat /etc/debian_version | cut -d. -f1)
    else
      os_ver=$(sed 's/\..*//' /etc/debian_version | tr -dc 'A-Za-z0-9')
    fi
  else
    os_ver=$(sed 's/\..*//' /etc/debian_version | tr -dc 'A-Za-z0-9')
  fi
  
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
  # 确保必要的网络工具可用
  if ! command -v ip >/dev/null 2>&1; then
    apt-get install -y iproute2 >/dev/null 2>&1 || true
  fi
  
  # 动态检测默认网络接口
  def_iface=$(ip route show default 2>/dev/null | awk '/default/ { print $5 }' | head -n1)
  
  # 如果默认路由检测失败，尝试其他方法
  if [ -z "$def_iface" ]; then
    if command -v route >/dev/null 2>&1; then
      def_iface=$(route 2>/dev/null | grep -m 1 '^default' | grep -o '[^ ]*$')
    fi
  fi
  
  if [ -z "$def_iface" ]; then
    def_iface=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -Po '(?<=dev )(\S+)')
  fi
  
  # 验证接口是否存在且处于活动状态
  if [ -n "$def_iface" ] && [ -d "/sys/class/net/$def_iface" ]; then
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
      echo "检测到网络接口: $NET_IFACE"
      return 0
    fi
  fi
  
  # 备选方案：检查常见接口名
  for iface in eth0 ens3 ens5 enp0s3 enp0s8; do
    if [ -d "/sys/class/net/$iface" ]; then
      iface_state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null)
      if [ "$iface_state" = "up" ]; then
        NET_IFACE="$iface"
        echo "使用网络接口: $NET_IFACE"
        return 0
      fi
    fi
  done
  
  exiterr "Could not detect the default network interface."
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
    exiterr "The specified DNS server is invalid."
  fi
}

check_server_dns() {
  if [ -n "$VPN_DNS_NAME" ] && ! check_dns_name "$VPN_DNS_NAME"; then
    exiterr "Invalid DNS name. 'VPN_DNS_NAME' must be a fully qualified domain name (FQDN)."
  fi
}

check_client_name() {
  if [ -n "$VPN_CLIENT_NAME" ]; then
    name_len="$(printf '%s' "$VPN_CLIENT_NAME" | wc -m)"
    if [ "$name_len" -gt "64" ] || printf '%s' "$VPN_CLIENT_NAME" | LC_ALL=C grep -q '[^A-Za-z0-9_-]\+' \
      || case $VPN_CLIENT_NAME in -*) true ;; *) false ;; esac; then
      exiterr "Invalid client name. No special characters except '-' and '_'."
    fi
  fi
}

check_subnets() {
  if [ -s /etc/ipsec.conf ] && grep -qs "script" /etc/sysctl.conf; then
    L2TP_NET=${VPN_L2TP_NET:-'192.168.18.0/24'}
    XAUTH_NET=${VPN_XAUTH_NET:-'192.168.19.0/24'}
    if ! grep -q "$L2TP_NET" /etc/ipsec.conf \
      || ! grep -q "$XAUTH_NET" /etc/ipsec.conf; then
      echo "Error: VPN subnets do not match initial install." >&2
      echo "       See docs to customize VPN subnets for more information." >&2
      exit 1
    fi
  fi
}

check_iptables() {
  if [ -x /sbin/iptables ] && ! iptables -nL INPUT >/dev/null 2>&1; then
    exiterr "IPTables check failed. Reboot and re-run this script."
  fi
}

start_setup() {
  bigecho "VPN setup in progress... Please be patient."
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
  bigecho "Installing packages required for setup..."
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
  
  # 多个IP检测服务
  check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- https://ip1.ipip.sh/ 2>/dev/null)
  check_ip "$public_ip" || public_ip=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short 2>/dev/null)
  check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- http://ipv4.icanhazip.com 2>/dev/null)
  check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- http://ip1.dynupdate.no-ip.com 2>/dev/null)
  check_ip "$public_ip" || public_ip=$(curl -s http://whatismyip.akamai.com/ 2>/dev/null)
  
  check_ip "$public_ip" || exiterr "Cannot detect this server's public IP. Define it as variable 'VPN_PUBLIC_IP' and re-run this script."
}

install_vpn_pkgs() {
  bigecho "Installing packages required for the VPN..."
  
  # 根据Debian版本选择合适的包
  if [ "$DEBIAN_VERSION" = "11" ]; then
    # Debian 11 软件包配置
    p1=libcurl4-nss-dev
  elif [ "$DEBIAN_VERSION" = "12" ]; then
    # Debian 12 软件包配置
    if apt-cache show libcurl4-gnutls-dev >/dev/null 2>&1; then
      p1=libcurl4-gnutls-dev
    else
      p1=libcurl4-nss-dev
    fi
  else
    # 默认配置
    p1=libcurl4-nss-dev
  fi
  
  (
    set -x
    apt-get -yqq install libnss3-dev libnspr4-dev pkg-config \
      libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
      $p1 flex bison gcc make libnss3-tools \
      libevent-dev libsystemd-dev uuid-runtime ppp xl2tpd >/dev/null
  ) || exiterr2
  
  # Debian 12特殊处理
  if [ "$DEBIAN_VERSION" = "12" ]; then
    (
      set -x
      apt-get -yqq install rsyslog >/dev/null
    ) || echo "警告: rsyslog安装失败"
  fi
}

install_fail2ban() {
  bigecho "Installing Fail2Ban to protect SSH..."
  (
    set -x
    apt-get -yqq install fail2ban >/dev/null
  ) || echo "警告: Fail2Ban安装失败"
}

link_scripts() {
  cd /opt/src || exit 1
  /bin/mv -f ikev2setup.sh ikev2.sh 2>/dev/null
  /bin/mv -f add_vpn_user.sh addvpnuser.sh 2>/dev/null
  /bin/mv -f del_vpn_user.sh delvpnuser.sh 2>/dev/null
  echo "Linking helper scripts..."
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
  if wget -t 3 -T 30 -q "$base1/$sc1" "$base1/$sc2" "$base1/$sc3" 2>/dev/null; then
    link_scripts
  else
    /bin/rm -f "$sc1" "$sc2" "$sc3"
    if wget -t 3 -T 30 -q "$base2/$sc1" "$base2/$sc2" "$base2/$sc3" 2>/dev/null; then
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
  swan_ver_latest=$(wget -t 2 -T 10 -qO- "$swan_ver_url" 2>/dev/null | head -n 1)
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
    && [ "$(find "$ipsec_bin" -mmin -10080 2>/dev/null)" ]; then
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
  if ! grep -qs "script" /etc/sysctl.conf; then
    conf_bk "/etc/sysctl.conf"
cat >> /etc/sysctl.conf <<EOF

# Added by VPN script
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
  if ! grep -qs "script" "$IPT_FILE"; then
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
    echo "# Modified by VPN script" > "$IPT_FILE"
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
  if ! grep -qs "script" /etc/rc.local; then
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

# Added by VPN script
(sleep $rc_delay
service ipsec restart
service xl2tpd restart
echo 1 > /proc/sys/net/ipv4/ip_forward)&
exit 0
EOF
  fi
}

start_services() {
  bigecho "Starting services..."
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

  # 创建检测脚本，使用检测到的网络接口
  cat > /usr/local/bin/check-vpn-rules.sh <<EOF
#!/bin/bash

NET_IFACE="$NET_IFACE"
RULE1="-s 192.168.19.0/24 -o \$NET_IFACE -m policy --dir out --pol none -j MASQUERADE"
RULE2="-s 192.168.18.0/24 -o \$NET_IFACE -j MASQUERADE"

if ! /sbin/iptables-save -t nat | grep -q -- "\$RULE1"; then
    /sbin/iptables -t nat -I POSTROUTING -s 192.168.19.0/24 -o \$NET_IFACE -m policy --dir out --pol none -j MASQUERADE
fi

if ! /sbin/iptables-save -t nat | grep -q -- "\$RULE2"; then
    /sbin/iptables -t nat -I POSTROUTING -s 192.168.18.0/24 -o \$NET_IFACE -j MASQUERADE
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

  bigecho "检测脚本已配置，使用网络接口: $NET_IFACE"
}

show_vpn_info() {
cat <<EOF

================================================
VPN服务器安装完成！

服务器IP: $public_ip
IPsec PSK: $VPN_IPSEC_PSK
用户名: $VPN_USER
密码: $VPN_PASSWORD

网络接口: $NET_IFACE
Debian版本: $DEBIAN_VERSION ($DEBIAN_CODENAME)

重要提示：
1. 请记录以上VPN连接信息
2. 系统将在5秒后自动重启以确保所有配置生效
3. 重启后VPN服务将自动启动

================================================
EOF
  
  if [ ! -e /dev/ppp ]; then
cat <<'EOF'
警告: 检测到容器环境，可能需要额外配置
================================================
EOF
  fi
  
  echo "系统将在5秒后重启..."
  sleep 5
  reboot
}

vpnsetup() {
  check_root
  check_vz
  check_lxc
  install_essential_tools  # 预安装必要工具并执行远程脚本
  upxtom
  check_os
  check_iface
  check_creds
  check_dns
  check_server_dns
  check_client_name
  check_subnets
  check_iptables
  disable_firewall
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
