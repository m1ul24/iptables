#!/bin/bash

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# 停止
/etc/init.d/iptables stop

# ポリシーの設定
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

# IP Spoofing攻撃対策
iptables -A INPUT -i eth0 -s 127.0.0.1/8 -j DROP
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i eth0 -s 192.168.0.0/16 -j DROP
iptables -A INPUT -i eth0 -s 192.168.0.0/24  -j DROP

# Ping攻撃対策
iptables -N PING_ATTACK
# Ping攻撃対策 + Ping Flood攻撃対策
iptables -A PING_ATTACK -m length --length :85 -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A PING_ATTACK -j LOG --log-prefix "[IPTABLES PINGATTACK] : " --log-level=debug
iptables -A PING_ATTACK -j DROP
iptables -A INPUT -p icmp --icmp-type 8 -j PING_ATTACK

# Smurf攻撃対策+不要ログ破棄
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A INPUT -d 224.0.0.1 -j DROP
iptables -A INPUT -d 153.126.187.255 -j DROP #ブロードキャストアドレス

# ステートフル・パケットインスペクションで正しいTCPと既に許可された接続を許可
iptables -A INPUT -p tcp ! --tcp-flags SYN,RST,ACK SYN -m state --state NEW -j DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

## ここから個別のサービスで利用するポートを開放する ##

# lo（ループバックインターフェース）の許可
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# SSH用のポートを許可
iptables -A INPUT -p tcp -m state --state NEW --dport 7272 -j ACCEPT

# http用のポート許可
# iptables -A INPUT -p tcp -m state --state NEW --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# DNS用ポートの許可。DNS Amp攻撃は適宜ログを取る
iptables -N DNSAMP
iptables -A DNSAMP -m recent --name dnsamp --set
iptables -A DNSAMP -m recent --name dnsamp --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "[IPTABLES DNSAMP] : " --log-level=debug
iptables -A DNSAMP -m recent --name dnsamp --rcheck --seconds 60 --hitcount 5 -j DROP
iptables -A DNSAMP -j ACCEPT

iptables -A INPUT -p udp -m state --state NEW --dport 53 -i eth0 -j DNSAMP

iptables -A INPUT -p tcp -m state --state NEW --dport 53 -j ACCEPT

# smtps用にポートを許可
iptables -A INPUT -p tcp -m state --state NEW --dport 465 -j ACCEPT

# imaps(pop3 protocol over TLS/SSL)用にポートを許可
iptables -A INPUT -p tcp -m state --state NEW --dport 993 -j ACCEPT

# pop3s(imap4 protocol over TLS/SSL)用にポートを許可
iptables -A INPUT -p tcp -m state --state NEW --dport 995 -j ACCEPT

# smtp tcp用にポートを許可
iptables -A INPUT -p tcp -m state --state NEW --dport 25 -j ACCEPT

# サブミッションポート用にポートを許可
iptables -A INPUT -p tcp -m state --state NEW --dport 587 -j ACCEPT

# https(http protocol over TLS/SSL) tcp用にポートを許可
iptables -A INPUT -p tcp -m state --state NEW --dport 443 -j ACCEPT

# rails用にポートを許可
iptables -A INPUT -p tcp -m state --state NEW --dport 3000 -j ACCEPT

# 上記の条件に当てはまらない通信を記録して破棄
iptables -A INPUT -m limit --limit 1/s -j LOG --log-prefix "[IPTABLES DROP INPUT] : " --log-level=debug
iptables -A INPUT -j DROP

# 設定を保存
/etc/init.d/iptables save

# 起動
/etc/init.d/iptables start
