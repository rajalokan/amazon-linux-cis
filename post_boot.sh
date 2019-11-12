#!/usr/bin/env bash

function _cis_mongo() {

    echo "Post boot CIS script for Mongo"
    sudo mount -o remount /var/tmp

    # 1.2.3
    mongo_repo_path="/etc/yum.repos.d/mongodb-org-4.0.repo"
    [[ -f $mongo_repo_path ]] && sudo sed -i 's/^gpgcheck=0$/gpgcheck=1/' $mongo_repo_path

    # 4.2.4
    sudo find /var/log -type f -exec chmod g-wx,o-rwx {} +
    sudo find /var/log -type d -exec chmod g-wx,o-rwx {} +
    sudo chmod 755 /var/log

    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP

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

    # 5.4.2 Ensure system accounts are non-login
    # TODO: Not working
    sudo usermod -s /usr/sbin/nologin mongod

    # iptables - General
    # Allow ssh
    allowed_ports="22"
    for port in $allowed_ports; do
        sudo iptables -A INPUT -p tcp --destination-port $port -m state --state NEW,ESTABLISHED -j ACCEPT
        sudo iptables -A OUTPUT -p tcp --source-port $port -m state --state ESTABLISHED -j ACCEPT
    done
    # Allow within subnet
    sudo iptables -A INPUT -s 192.168.0.0/18 -j ACCEPT
    sudo iptables -A FORWARD -s 192.168.0.0/18 -j ACCEPT
    sudo iptables -A OUTPUT -s 192.168.0.0/18 -j ACCEPT
    # # Allow for AWS Inspector
    # inspector_ports="443 80"
    # for port in $inspector_ports; do
    #     sudo iptables -A OUTPUT -p tcp --dport $port -j ACCEPT
    #     sudo iptables -A FORWARD -p tcp --dport $port -j ACCEPT
    #     sudo iptables -A OUTPUT -d 52.219.64.121/32 -J ACCEPT
    # done
    # AWS_AGENT_PID=$(pidof /opt/aws/awsagent/bin/awsagent)
    # sudo iptables -m owner -p tcp -- pid-owner ${AWS_AGENT_PID} -j REJECT

    # 3.5.1.4 Ensure firewall rules exist for all open ports
    tcp_ports="27017 111 22 25"
    for port in $tcp_ports; do
        sudo iptables -A INPUT -p tcp  -s 192.168.0.0/18 --dport $port -j ACCEPT
    done
    #
    udp_ports="975 858 857 68 111 323"
    for port in $udp_ports; do
        sudo iptables -A INPUT -p udp  -s 192.168.0.0/18 --dport $port -j ACCEPT
        sudo iptables -A OUTPUT -p udp  -s 192.168.0.0/18 --sport $port -j ACCEPT
    done

    # 3.5.1.1 Ensure default deny firewall policy
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT


    # Proto  Send-Q Local Address           State
    # tcp         0 0.0.0.0:27017           LISTEN
    # tcp         0 0.0.0.0:111             LISTEN
    # tcp         0 0.0.0.0:22              LISTEN
    # tcp         0 127.0.0.1:25            LISTEN
    # tcp6        0 :::111                  LISTEN
    # tcp6        0 :::22                   LISTEN
    # udp         0 0.0.0.0:858
    # udp         0 0.0.0.0:68
    # udp         0 0.0.0.0:111
    # udp         0 127.0.0.1:323
    # udp6        0 :::858
    # udp6        0 :::111
    # udp6        0 ::1:323

    # 1.6.1.4
    # TODO: Still shows up
}

function _cis_presto() {
    #statements
    echo "Post boot CIS script for Presto"

    # 4.2.4
    sudo find /var/log -type f -exec chmod g-wx,o-rwx {} +
    sudo find /var/log -type d -exec chmod g-wx,o-rwx {} +
    sudo chmod 755 /var/log

    echo "Configuring /tmp"
    sudo systemctl unmask tmp.mount
    sudo systemctl daemon-reload
    sudo systemctl enable --now tmp.mount
    #
    sudo sed -i 's/Options=.*/&,noexec,nodev,nosuid/' /usr/lib/systemd/system/tmp.mount
    #
    # Re mount for it to reflect
    sudo mount -o remount,nodev /tmp
    sudo mount -o remount,nosuid /tmp
    sudo mount -o remount,noexec /tmp

    sudo mount -o remount /var/tmp

    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP

    sudo sysctl -w net.ipv4.ip_forward=0

    sudo tee -a /etc/sysctl.d/99-CIS.conf > /dev/null <<EOF

# 3.1.1 Ensure IP forwarding is disabled
net.ipv4.ip_forward=0
EOF

    # 3.5.1.4 Ensure firewall rules exist for all open ports
    tcp_ports="39137 111 22 25"
    for port in $tcp_ports; do
        sudo iptables -A INPUT -p tcp  -s 192.168.0.0/18 --dport $port -j ACCEPT
        sudo iptables -A OUTPUT -p tcp  -s 192.168.0.0/18 --sport $port -j ACCEPT
    done
    #
    udp_ports="323 967 8125 68 111"
    for port in $udp_ports; do
        sudo iptables -A INPUT -p udp  -s 192.168.0.0/18 --dport $port -j ACCEPT
        sudo iptables -A OUTPUT -p udp  -s 192.168.0.0/18 --sport $port -j ACCEPT
    done
}

function _cis_eks() {
    #statements
    echo "Post boot CIS script for EKS"
    sudo mount -o remount /var/tmp

    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP

    # 4.2.4
    sudo find /var/log -type f -exec chmod g-wx,o-rwx {} +
    sudo find /var/log -type d -exec chmod g-wx,o-rwx {} +
    sudo chmod 755 /var/log
}

case $1 in
    mongo )
        _cis_mongo
        ;;
    presto )
        _cis_presto
        ;;
    eks )
        _cis_presto
        ;;
    * )
        echo "Invalid entry...."
        echo "Usage : post_boot.sh <mongo|presto|eks>"
        exit 0
        ;;
esac

use admin
db.createUser(
  {
    user: "atlanuser",
    pwd: passwordPrompt(), // or cleartext password
    roles: [ { role: "userAdminAnyDatabase", db: "admin" }, "readWriteAnyDatabase" ]
  }
)
