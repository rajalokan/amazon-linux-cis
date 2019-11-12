#!/usr/bin/env bash

# 1.1.2 Ensure /tmp is configured
# 1.1.4
# 1.1.5
sudo mount -o remount,nosuid /tmp
sudo mount -o remount,noexec /tmp

# 1.1.6, 7, 11, 12, 13

## 1.1.17 Ensure noexec option set on /dev/shm partition
if [[ $(grep -Pq '/dev/shm' /etc/fstab) ]]; then
    echo "true"
    sudo sed -i 's:^tmpfs.*/dev/shm.*:tmpfs\t    /dev shm\ttmpfs\tdefaults,rw,nosuid,nodev,noexec\t0   0:' /etc/fstab
else
    echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' | sudo tee -a /etc/fstab
fi
# Re mount for it to reflect
sudo mount -o remount,nodev /dev/shm
sudo mount -o remount,noexec /dev/shm

# 1.2.3
# TODO: Verify this
sudo sed -i 's/^gpgcheck=0$/gpgcheck=1/' /etc/yum.repos.d/*.repo

# 1.6.1.2
# 1.6.1.3
# 1.6.1.6

# 3.5.1.1
# 3.5.1.2
# 3.5.1.4

# 4.2.4
# TODO: Still there
sudo find /var/log -type f -exec chmod g-wx,o-rwx {} +
sudo find /var/log -type d -exec chmod g-wx,o-rwx {} +
sudo chmod 755 /var/log


# 5.4.2 Ensure system accounts are non-login
# TODO: Still there
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
    if [[ $user != "root" ]]; then
        usermod -L $user
        if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
            usermod -s /usr/sbin/nologin $user
        fi
    fi
done
# TODO: Need to ensure this runs for mongod user
sudo usermod -s /usr/sbin/nologin mongod

# 6.2.8
# Note: Not needed
for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
    dirperm=`ls -ld $dir | cut -f1 -d" "`
    if [ `echo $dirperm | cut -c6 ` != "-" ]; then
        echo "Group Write permission set on directory $dir. Revoking it"
        sudo chmod g-w $dir
    fi
    if [ `echo $dirperm | cut -c8 ` != "-" ]; then
        echo "Other Read permission set on directory $dir. Revoking it"
        sudo chmod o-r $dir
    fi
    if [ `echo $dirperm | cut -c9 ` != "-" ]; then
        echo "Other Write permission set on directory $dir. Revoking it"
        sudo chmod o-w $dir
    fi
    if [ `echo $dirperm | cut -c10 ` != "-" ]; then
        echo "Other Execute permission set on directory $dir. Revoking it"
        sudo chmod o-x $dir
    fi
done

# 6.2.9
# TODO: Still there
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then
  # if [ $uid -ge 1000 ]; then
    owner=$(stat -L -c "%U" "$dir" 2>&1)
    if [[ $? -ne 0 && $owner == "stat: cannot stat '$dir': No such file or directory" ]]; then
        echo "Creating dir $dir and allowing permission for user: ${user}"
        # sudo mkdir -p ${dir}
        # sudo chown ${user}:${user} ${dir}
    fi
    if [ "$owner" != "$user" ]; then
        echo "The home directory ($dir) of user $user is owned by $owner."
        # sudo chown ${user}:${user} ${dir}
    fi
  fi
done
# sudo chown nfsnobody:nfsnobody /var/lib/nfs




sudo pvcreate /dev/xvdi
sudo vgcreate vg0 /dev/xvdi

sudo lvcreate -l 15%FREE -n var_log_audit vg0
sudo mkfs.ext4 /dev/vg0/var_log_audit
sudo mkdir -p /var/log/audit
echo "/dev/mapper/vg0-var_log_audit /var/log/audit ext4 defaults 0 2" | sudo tee -a /etc/fstab

sudo lvcreate -l 40%FREE -n var_log vg0
sudo mkfs.ext4 /dev/vg0/var_log
sudo mkdir -p /var/log
echo "/dev/mapper/vg0-var_log /var/log ext4 defaults 0 2" | sudo tee -a /etc/fstab

sudo lvcreate -l 30%FREE -n var_tmp vg0
sudo mkfs.ext4 /dev/vg0/var_tmp
sudo mkdir -p /var/tmp
echo "/dev/mapper/vg0-var_tmp /var/tmp ext4 defaults 0 2" | sudo tee -a /etc/fstab

sudo lvcreate -l 30%FREE -n var_tmp vg0
sudo mkfs.ext4 /dev/vg0/var_tmp
sudo mkdir -p /var/tmp
echo "/dev/mapper/vg0-var_tmp /var/tmp ext4 defaults 0 2" | sudo tee -a /etc/fstab

sudo mount -a



sudo iptables -A INPUT -p tcp --sport 22 -j ACCEPT

sudo iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

sudo iptables -A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT




sudo cp /etc/default/grub /etc/default/grub.bak
sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=\"console=tty0 console=ttyS0,115200n8 /GRUB_CMDLINE_LINUX_DEFAULT=\"console=ttyS0,115200n8 console=tty0 selinux=1 security=selinux enforcing=1 /g' /etc/default/grub


# 1.6.1.2 Ensure the SELinux state is enforcing
sudo yum -y update
sudo yum -y install policycoreutils selinux-policy-targeted policycoreutils-python
sudo rm -f /etc/sysconfig/selinux
sudo ln -s /etc/selinux/config /etc/sysconfig/selinux
sudo sed -i 's/SELINUX=.*/SELINUX=enforcing/g' /etc/selinux/config
# 1.6.1.3 Ensure SELinux policy is configured
sudo sed -i 's/SELINUXTYPE=.*/SELINUXTYPE=targeted/g' /etc/selinux/config
sudo semanage fcontext -a -t shell_exec_t /bin/bash
sudo restorecon -rFv /
sudo touch /.autorelabel
sudo systemctl enable rhel-autorelabel-mark.service
sudo systemctl enable rhel-autorelabel.service
#
sudo reboot
