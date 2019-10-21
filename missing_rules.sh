#!/usr/bin/env bash

sudo tee -a /etc/modprobe.d/CIS.conf > /dev/null << EOF

# 1.1.1.1
install cramfs /bin/true
# 1.1.1.2
install hfs /bin/true
# 1.1.1.3
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
# 3.4.1
install dccp /bin/true
# 3.4.2
install sctp /bin/true
# 3.4.3
install rds /bin/true
# 3.4.4
install tipc /bin/true
EOF
#
sudo rmmod cramfs
sudo rmmod hfs
sudo rmmod hfsplus
sudo rmmod squashfs
sudo rmmod udf

# # 1.1.2 Ensure /tmp is configured
# sudo systemctl unmask tmp.mount
# sudo systemctl daemon-reload
# sudo systemctl enable --now tmp.mount
# #
# sudo sed -i 's/Options=.*/&,noexec,nodev,nosuid/' /usr/lib/systemd/system/tmp.mount
# #
# # Re mount for it to reflect
# sudo mount -o remount,nodev /tmp

## 1.1.17 Ensure noexec option set on /dev/shm partition
grep -Pq '/dev/shm' /etc/fstab \
    && sudo sed -i 's:^tmpfs.*/dev/shm.*:tmpfs\t    /dev/shm\ttmpfs\tdefaults,rw,nosuid,nodev,noexec\t0   0:' /etc/fstab \
    || echo 'tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0' | sudo tee -a /etc/fstab
# Re mount for it to reflect
sudo mount -o remount,nodev /dev/shm

# 1.3.1
sudo yum -y install aide
#
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 1.3.2
(sudo crontab -l 2>/dev/null; echo "0 5 * * * /usr/sbin/aide --check") | sudo crontab -

## 1.4.1 Ensure permissions on bootloader config are configured
sudo chown root:root /boot/grub2/grub.cfg
sudo chmod og-rwx /boot/grub2/grub.cfg

# 1.5.1
sudo tee -a /etc/security/limits.d/CIS.conf > /dev/null << EOF
* hard core 0
EOF
#
sudo sysctl -w fs.suid_dumpable=0

# 1.6.1.2 Ensure the SELinux state is enforcing
sudo sed -i 's/SELINUX=.*/SELINUX=enforcing/g' /etc/selinux/config

# 1.6.1.3 Ensure SELinux policy is configured
sudo sed -i 's/SELINUXTYPE=.*/SELINUXTYPE=targeted/g' /etc/selinux/config

# 1.6.1.6 Ensure no unconfined daemons exist
# ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'


# 1.7.1.2
echo "Authorized uses only. All activity may be monitored and reported." | sudo tee /etc/issue

# 1.7.1.3
echo "Authorized uses only. All activity may be monitored and reported." | sudo tee /etc/issue.net

# 2.1.2
sudo yum remove -y xorg-x11*

# sudo tee -a /etc/sysctl.d/99-CIS.conf > /dev/null <<EOF
# # 1.5.1
# fs.suid_dumpable = 0
#
# # 1.5.2
# kernel.randomize_va_space = 2
#
# # 3.1.1 Ensure IP forwarding is disabled
# net.ipv4.ip_forward = 0
# net.ipv6.conf.all.forwarding = 0
#
# # 3.1.2 Ensure packet redirect sending is disabled
# net.ipv4.conf.all.send_redirects = 0
# net.ipv4.conf.default.send_redirects = 0
#
# # 3.2.1 Ensure source routed packets are not accepted
# net.ipv4.conf.all.accept_source_route = 0
# net.ipv4.conf.default.accept_source_route = 0
# net.ipv6.conf.all.accept_source_route = 0
# net.ipv6.conf.default.accept_source_route = 0
#
# # 3.2.2 ICMP Redirects not accepted
# net.ipv4.conf.all.accept_redirects = 0
# net.ipv4.conf.default.accept_redirects = 0
# net.ipv6.conf.all.accept_redirects = 0
# net.ipv6.conf.default.accept_redirects = 0
#
# # 3.2.3 Secure ICMP redirects not accepted
# net.ipv4.conf.all.secure_redirects = 0
# net.ipv4.conf.default.secure_redirects = 0
#
# # 3.2.4 Ensure suspicious packets are logged
# net.ipv4.conf.all.log_martians = 1
# net.ipv4.conf.default.log_martians = 1
#
# # 3.2.5
# net.ipv4 .icmp_echo_ignore_broadcasts = 1
#
# # 3.2.6
# net.ipv4.icmp_ignore_bogus_error_responses = 1
#
# # 3.2.7
# net.ipv4.conf.all.rp_filter = 1
# net.ipv4.conf.default.rp_filter = 1
#
# # 3.2.8
# net.ipv4.tcp_syncookies = 1
#
# # 3.2.9 Ensure IPv6 router advertisements are not accepted
# net.ipv6.conf.all.accept_ra = 0
# net.ipv6.conf.default.accept_ra = 0
# EOF
#
# # 1.5.2
# sudo sysctl -w kernel.randomize_va_space=2
#
# # 3.1.2
# sudo sysctl -w net.ipv4.ip_forward=0
# sudo sysctl -w net.ipv6.conf.all.forwarding=0
# sudo sysctl -w net.ipv4.route.flush=1
# sudo sysctl -w net.ipv6.route.flush=1
# # 3.1.2
# sudo sysctl -w net.ipv4.conf.all.send_redirects=0
# sudo sysctl -w net.ipv4.conf.default.send_redirects=0
# sudo sysctl -w net.ipv4.route.flush=1
# # 3.2.1
# sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
# sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
# sudo sysctl -w net.ipv6.conf.all.accept_source_route=0
# sudo sysctl -w net.ipv6.conf.default.accept_source_route=0
# sudo sysctl -w net.ipv4.route.flush=1
# sudo sysctl -w net.ipv6.route.flush=1
# # 3.2.2
# sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
# sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
# sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
# sudo sysctl -w net.ipv6.conf.default.accept_redirects=0
# sudo sysctl -w net.ipv4.route.flush=1
# sudo sysctl -w net.ipv6.route.flush=1
#
# # 3.2.3
# sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
# sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
# sudo sysctl -w net.ipv4.route.flush=1
#
# # 3.2.4
# sudo sysctl -w net.ipv4.conf.all.log_martians=1
# sudo sysctl -w net.ipv4.conf.default.log_martians=1
# sudo sysctl -w net.ipv4.route.flush=1
# # 3.2.5
# sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
# sudo sysctl -w net.ipv4.route.flush=1
# # 3.2.6
# sudo sysctl -w net.ipv4.route.flush=1
# # 3.2.7
# sudo sysctl -w net.ipv4.conf.all.rp_filter=1
# sudo sysctl -w net.ipv4.conf.default.rp_filter=1
# sudo sysctl -w net.ipv4.route.flush=1
# # 3.2.8
# sudo sysctl -w net.ipv4.tcp_syncookies=1
# sudo sysctl -w net.ipv4.route.flush=1
# # 3.2.9
# sudo sysctl -w net.ipv6.conf.all.accept_ra=0
# sudo sysctl -w net.ipv6.conf.default.accept_ra=0
# sudo sysctl -w net.ipv6.route.flush=1

# 3.3.3 Ensure /etc/hosts.deny is configured
echo "ALL: ALL" | sudo tee -a /etc/hosts.deny
echo "ALL: ALL" | sudo tee -a /etc/hosts.allow


# # 3.5.1.1
# iptables -P INPUT DROP
# iptables -P OUTPUT DROP
# iptables -P FORWARD DROP
#
# # 3.5.1.2
# iptables -A INPUT -i lo -j ACCEPT
# iptables -A OUTPUT -o lo -j ACCEPT
# iptables -A INPUT -s 127.0.0.0/8 -j DROP
#
#
#
# # 3.5.2.1
# ip6tables -P INPUT DROP
# ip6tables -P OUTPUT DROP
# ip6tables -P FORWARD DROP
#
# # 3.5.2.2
# ip6tables -A INPUT - i lo -j ACCEPT
# ip6tables -A OUTPUT -o lo -j ACCEPT
# ip6tables -A INPUT -s ::1 -j DROP


# ## 3.5.1.2 Ensure IPv4 loopback traffic is configured
# sudo iptables -A INPUT -i lo -j ACCEPT
# sudo iptables -A OUTPUT -o lo -j ACCEPT
# sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP

# ## 3.5.2.2 Ensure IPv6 loopback traffic is configured
sudo ip6tables -A INPUT -i lo -j ACCEPT
sudo ip6tables -A OUTPUT -o lo -j ACCEPT
sudo ip6tables -A INPUT -s ::1 -j DROP


###########TODO##########
## 3.5.2.1 Ensure IPv4 default deny firewall policy

##########TODO###########
# sudo iptables -P INPUT DROP
# sudo iptables -P OUTPUT DROP
# sudo iptables -P FORWARD DROP


## 3.5.2.1 Ensure IPv6 default deny firewall policy
sudo ip6tables -P INPUT DROP
sudo ip6tables -P OUTPUT DROP
sudo ip6tables -P FORWARD DROP

# # 3.5.1.4 Ensure firewall rules exist for all open ports
# sudo iptables -A INPUT -p tcp --match multiport --dports 0:65535 -j ACCEPT
# sudo iptables -A OUTPUT -p tcp --match multiport --dports 0:65535 -j ACCEPT

# 3.6 Disable ipV6
sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*/& ipv6.disable=1/' /etc/default/grub
sudo grub2-mkconfig -o /boot/grub2/grub.cfg

# 4.1.3 Ensure auditing for processes that start prior to auditd is enabled
sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*/& audit=1/' /etc/default/grub
sudo grub2-mkconfig -o /boot/grub2/grub.cfg

# 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host
sudo sed -i '/^#\*\.\* @@remote-host:514/s/^#//' /etc/rsyslog.conf
sudo pkill -HUP rsyslogd

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

# 4.1.1.2
sudo sed -i 's/space_left_action =.*/space_left_action = email/g' /etc/audit/auditd.conf
sudo sed -i 's/admin_space_left_action =.*/admin_space_left_action = halt/g' /etc/audit/auditd.conf

# 4.1.1.3
sudo sed -i 's/max_log_file_action =.*/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf

# 4.2.4
sudo find /var/log -type f -exec chmod g-wx,o-rwx {} +

# 5.2.4
echo "Protocol 2" | sudo tee -a /etc/ssh/sshd_config

# 5.2.5
sudo sed -i 's/#.*LogLevel.*/LogLevel INFO/g' /etc/ssh/sshd_config

# 5.2.6
sudo sed -i 's/X11Forwarding.*/X11Forwarding no/g' /etc/ssh/sshd_config

# 5.2.7
sudo sed -i 's/#.*MaxAuthTries.*/MaxAuthTries 4/g' /etc/ssh/sshd_config

# 5.2.8
sudo sed -i 's/#.*IgnoreRhosts.*/IgnoreRhosts yes/g' /etc/ssh/sshd_config

# 5.2.9
sudo sed -i 's/#.*HostbasedAuthentication.*/HostbasedAuthentication no/g' /etc/ssh/sshd_config

# 5.2.10
sudo sed -i 's/#.*PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config

# 5.2.11
sudo sed -i 's/#.*PermitEmptyPasswords.*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config

# 5.2.12
sudo sed -i 's/#.*PermitUserEnvironment.*/PermitUserEnvironment no/g' /etc/ssh/sshd_config

# 5.2.13
sudo tee -a /etc/ssh/sshd_config > /dev/null << EOF
#
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
EOF

# 5.2.14
sudo tee -a /etc/ssh/sshd_config > /dev/null << EOF
#
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
EOF

# 5.2.15
sudo tee -a /etc/ssh/sshd_config > /dev/null << EOF
#
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
EOF

# 5.2.16
sudo sed -i 's/#.*ClientAliveInterval*.*/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sudo sed -i 's/#.*ClientAliveCountMax.*/ClientAliveCountMax 0/g' /etc/ssh/sshd_config

# 5.2.17
sudo sed -i 's/#.*LoginGraceTime.*/LoginGraceTime 60/g' /etc/ssh/sshd_config

# # 5.2.18
# AllowUsers <userlist>AllowGroups <grouplist>DenyUsers <userlist>DenyGroups<grouplist>

# 5.2.19
sudo sed -i 's/#.*Banner.*/Banner \/etc\/issue.net/g' /etc/ssh/sshd_config

# 5.4.2 Ensure system accounts are non-login
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
    if [[ $user != "root" ]]; then
        usermod -L $user
        if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
            usermod -s /usr/sbin/nologin $user
        fi
    fi
done


# 5.4.4
# 5.4.5
sudo tee -a /etc/bashrc > /dev/null << EOF
#
umask 027
#
TMOUT=600
EOF
#
sudo tee -a /etc/profile > /dev/null << EOF
#
umask 027
# 5.4.5
TMOUT=600
EOF
#
sudo tee -a /etc/profile.d/*.sh >/dev/null <<EOF
umask 027
EOF

# # 6.2.7
# cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
#   if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
#     echo "The home directory ($dir) of user $user does not exist."
#   fi
# done

# # 6.2.8
# for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
#   dirperm=`ls -ld $dir | cut -f1 -d" "`
#   if [ `echo $dirperm | cut -c6 ` != "-" ]; then
#     echo "Group Write permission set on directory $dir"
#   fi
#   if [ `echo $dirperm | cut -c8 ` != "-" ]; then
#     echo "Other Read permission set on directory $dir"
#   fi
#   if [ `echo $dirperm | cut -c9 ` != "-" ]; then
#     echo "Other Write permission set on directory $dir"
#   fi
#   if [ `echo $dirperm | cut -c10 ` != "-" ]; then
#     echo "Other Execute permission set on directory $dir"
#   fi
# done

# # 6.2.9
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  # if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then
  if [ $uid -ge 1000 ]; then
      owner=$(stat -L -c "%U" "$dir")
      if [ "$owner" != "$user" ]; then
        echo "The home directory ($dir) of user $user is owned by $owner."
        sudo chown ${user}:${user} ${dir}
      fi
  fi
done
# sudo chown nfsnobody:nfsnobody /var/lib/nfs

echo "CIS hardening successful"
