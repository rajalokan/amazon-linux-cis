#!/usr/bin/env bash

# Common //////////////////////////////////////////////////////////////////////

function remount_var_tmp() {
    sudo mount -o remount /var/tmp
}

function gpg_check() {
    mongo_repo_path="/etc/yum.repos.d/mongodb-org-4.2.repo"
    [[ -f $mongo_repo_path ]] && sudo sed -i 's/^gpgcheck=0$/gpgcheck=1/' $mongo_repo_path
}

function clean_logs() {
    # 4.2.4
    sudo find /var/log -type f -exec chmod g-wx,o-rwx {} +
    sudo find /var/log -type d -exec chmod g-wx,o-rwx {} +
    sudo chmod 755 /var/log
}

function iptables_loopback() {
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP
}

function system_accounts_not_login() {
    echo "Currently not working"
    # 5.4.2 Ensure system accounts are non-login
    # TODO: Not working
    # sudo usermod -s /usr/sbin/nologin mongod
}

# function configure_tmp() {
#     echo "Configuring /tmp"
#     sudo systemctl unmask tmp.mount
#     sudo systemctl daemon-reload
#     sudo systemctl enable --now tmp.mount
#     #
#     sudo sed -i 's/Options=.*/&,noexec,nodev,nosuid/' /usr/lib/systemd/system/tmp.mount
#     #
#     # Re mount for it to reflect
#     sudo mount -o remount,nodev /tmp
#     sudo mount -o remount,nosuid /tmp
#     sudo mount -o remount,noexec /tmp
# }
#
# function disable_ipv4_forward() {
#     sudo sysctl -w net.ipv4.ip_forward=0
#     sudo tee -a /etc/sysctl.d/99-CIS.conf > /dev/null <<EOF
#
# # 3.1.1 Ensure IP forwarding is disabled
# net.ipv4.ip_forward=0
# EOF
# }

function run_audit_rules() {
    sudo tee -a /etc/audit/audit.rules >> /dev/null <<EOF
# 4.1.4
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
# 4.1.5
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
# 4.1.6
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
# 4.1.7
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
# 4.1.8
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
# 4.1.9
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
# 4.1.10
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
# 4.1.11
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
# 4.1.13
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
# 4.1.14
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
# 4.1.15
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
# 4.1.16
-w /var/log/sudo.log -p wa -k actions
# 4.1.17
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
# 4.1.18
-e 2
EOF
}

# # ///////////////////////////// Iptables //////////////////////////////////////
#
# function allow_ssh() {
#     # Allow ssh
#     allowed_ports="22"
#     for port in $allowed_ports; do
#         sudo iptables -A INPUT -p tcp --destination-port $port -m state --state NEW,ESTABLISHED -j ACCEPT
#         sudo iptables -A OUTPUT -p tcp --source-port $port -m state --state ESTABLISHED -j ACCEPT
#     done
# }
#
# function allow_http_n_https() {
#     # allow HTTP inbound and replies (for AWS Inspector)
#     sudo iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
#     sudo iptables -A OUTPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
#     #
#     # allow HTTPS inbound and replies
#     sudo iptables -A INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
#     sudo iptables -A OUTPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
#
#     # root can initiate HTTP outbound (for yum)
#     sudo iptables -A OUTPUT -p tcp --dport 80 -m owner --uid-owner root -m state --state NEW,ESTABLISHED -j ACCEPT
#     # anyone can receive replies (ok since connections can't be initiated)
#     sudo iptables -A INPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
# }
#
# function allow_dns() {
#     # root can do DNS searches (if your Subnet is 10.0.0.0/24 AWS DNS seems to be on 10.0.0.2)
#     # if your subnet is different, change 10.0.0.2 to your value (eg a 172.31.1.0/24 Subnet would be 172.31.1.2)
#     # see http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-dns.html
#     # DNS = start subnet range "plus two"
#     sudo iptables -D OUTPUT -p udp --dport 53 -m owner --uid-owner root -d 192.168.0.0/18 -j ACCEPT
#     sudo iptables -D INPUT -p udp --sport 53 -s 192.168.0.0/18 -j ACCEPT
# }
#
# function allow_inside_subnet() {
#     # Allow within subnet
#     sudo iptables -A INPUT -s 192.168.0.0/18 -j ACCEPT
#     sudo iptables -A FORWARD -s 192.168.0.0/18 -j ACCEPT
#     sudo iptables -A OUTPUT -s 192.168.0.0/18 -j ACCEPT
# }
#
# function drop_all() {
#     # now drop everything else
#     # 3.5.1.1 Ensure default deny firewall policy
#     sudo iptables -P INPUT DROP
#     sudo iptables -P FORWARD DROP
#     sudo iptables -P OUTPUT DROP
# }
#
# function allow_all() {
#     sudo iptables -P INPUT ACCEPT
#     sudo iptables -P FORWARD ACCEPT
#     sudo iptables -P OUTPUT ACCEPT
# }
#
# function allow_replicated() {
#     #statements
#     replicated_get_ips="54.165.10.106 52.91.83.38 54.86.176.181 34.194.217.225 34.200.116.158"
#     replicated_api_ips= "54.174.248.164 54.236.191.206 54.172.64.205 54.173.15.255 107.23.48.227 18.211.10.161"
#     replicated_registry_ips="54.175.57.8 54.226.216.146 50.19.197.213 54.236.144.143"
#     for ip in $replicated_get_ips; do
#         sudo iptables -A INPUT -p tcp -s $ip -j ACCEPT
#     done
#     for ip in $replicated_api_ips; do
#         sudo iptables -A INPUT -p tcp -s $ip -j ACCEPT
#     done
#     for ip in $replicated_registry_ips; do
#         sudo iptables -A INPUT -p tcp -s $ip -j ACCEPT
#     done
#     sudo iptables -A INPUT -p icmp -j ACCEPT
#
# }
#
# function allow_eks() {
#     #statements
#     # 1025-65535
#     allow_ssh
#     allow_http_n_https
#     allow_inside_subnet
#     drop_all
#
#     eks_ports="32157 443 10250 32348 31907"
#     for port in $eks_ports; do
#         sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT
#     done
#     sudo iptables -A INPUT -p tcp --dport 1025:65535 -j ACCEPT
#
#     sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
#     sudo iptables -A INPUT -p udp --sport 53 -j ACCEPT
#
#     sudo iptables -P INPUT DROP
#     sudo iptables -P FORWARD ACCEPT
#     sudo iptables -P OUTPUT ACCEPT
# }
#
# # function firewall_rules_for_all_open_ports() {
# # }
#
# function mongo_iptables() {
#     allow_ssh
#     allow_inside_subnet
#     drop_all
# }
#
# function presto_iptables() {
#     allow_ssh
#     allow_inside_subnet
#     drop_all
# }
#
# function eks_iptables() {
#     allow_ssh
#     allow_replicated
#     drop_all
#     sudo iptables -A INPUT -p icmp -j ACCEPT
# }

# //////////////////////////////// CIS ////////////////////////////////////////

function _cis_mongo() {
    echo "Post boot CIS script for Mongo"
    run_audit_rules
    clean_logs
    iptables_loopback
    system_accounts_not_login
    # mongo_iptables
    echo "Post boot CIS hardening successful"
}

function _cis_eks() {
    echo "Post boot CIS script for EKS"
    remount_var_tmp
    run_audit_rules
    clean_logs
    # eks_iptables
    echo "Post boot CIS hardening successful"
}

function _cis_presto() {
    echo "Post boot CIS script for Presto"
    clean_logs
    configure_tmp
    remount_var_tmp
    iptables_loopback
    disable_ipv4_forward
    presto_iptables
    sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
    sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
}


case $1 in
    mongo )
        _cis_mongo
        ;;
    presto )
        _cis_presto
        ;;
    eks )
        _cis_eks
        ;;
    * )
        echo "Invalid entry...."
        echo "Usage : post_boot.sh <mongo|presto|eks>"
        exit 0
        ;;
esac
