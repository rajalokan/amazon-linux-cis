#!/usr/bin/env bash

function _cis_mongo() {

    echo "Post boot CIS script for Mongo"
    # 1.2.3
    mongo_repo_path="/etc/yum.repos.d/mongodb-org-4.0.repo"
    [[ -f $mongo_repo_path ]] && sudo sed -i 's/^gpgcheck=0$/gpgcheck=1/' $mongo_repo_path

    # 4.2.4
    sudo find /var/log -type f -exec chmod g-wx,o-rwx {} +
    sudo find /var/log -type d -exec chmod g-wx,o-rwx {} +
    sudo chmod 755 /var/log

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
    # Allow for AWS Inspector
    inspector_ports="443 80"
    for port in $inspector_ports; do
        sudo iptables -A OUTPUT -p tcp --dport $port -j ACCEPT
        sudo iptables -A FORWARD -p tcp --dport $port -j ACCEPT
        sudo iptables -A OUTPUT -d 52.219.64.121/32 -J ACCEPT
        52.95.88.105/32
    done
    # AWS_AGENT_PID=$(pidof /opt/aws/awsagent/bin/awsagent)
    # sudo iptables -m owner -p tcp -- pid-owner ${AWS_AGENT_PID} -j REJECT

    # 3.5.1.4 Ensure firewall rules exist for all open ports
    tcp_ports="27017 111 22 25"
    for port in $tcp_ports; do
        sudo iptables -A INPUT -p tcp  -s 192.168.0.0/18 --dport $port -j ACCEPT
    done
    #
    udp_ports="858 857 68 111 323"
    for port in $udp_ports; do
        sudo iptables -A INPUT -p udp  -s 192.168.0.0/18 --dport $port -j ACCEPT
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


    # Create partitions
    sudo pvcreate /dev/nvme1n1
    sudo vgcreate vg1 /dev/nvme1n1

    # var
    sudo lvcreate -l 60%FREE -n var vg1
    sudo mkfs.ext4 /dev/vg1/var
    sudo mkdir -p /mnt/var
    sudo mount /dev/vg1/var /mnt/var
    sudo rsync -aulvXpogtr /var/* /mnt/var
    sudo rsync -aulvXpogtr /var/* /mnt/var
    sudo umount /mnt/var
    echo "/dev/vg1/var   /var       ext4    defaults,noatime,nofail 0   2" | sudo tee -a /etc/fstab
    sudo mv /var /var.old
    sudo mkdir -p /var
    sudo mount /dev/mapper/vg1-var /var

    # var_tmp
    sudo lvcreate -l 33%FREE -n var_tmp vg1
    sudo mkfs.ext4 /dev/vg1/var_tmp
    sudo mkdir -p /mnt/var_tmp
    sudo mount /dev/vg1/var_tmp /mnt/var_tmp
    sudo rsync -aulvXpogtr /var/tmp/* /mnt/var_tmp
    sudo rsync -aulvXpogtr /var/tmp/* /mnt/var_tmp
    sudo umount /mnt/var_tmp
    echo "/dev/vg1/var_tmp   /var/tmp       ext4    defaults,noatime,nofail,noexec,nodev,nosuid 0   2" | sudo tee -a /etc/fstab
    sudo mv /var/tmp /var_tmp.old
    sudo mkdir -p /var/tmp
    sudo mount /dev/mapper/vg1-var_tmp /var/tmp

    # var_log
    sudo lvcreate -l 50%FREE -n var_log vg1
    sudo mkfs.ext4 /dev/vg1/var_log
    sudo mkdir -p /mnt/var_log
    sudo mount /dev/vg1/var_log /mnt/var_log
    sudo rsync -aulvXpogtr /var/log/* /mnt/var_log
    sudo rsync -aulvXpogtr /var/log/* /mnt/var_log
    sudo umount /mnt/var_log
    echo "/dev/vg1/var_log   /var/log       ext4    defaults,noatime,nofail 0   2" | sudo tee -a /etc/fstab
    sudo mv /var/log /var_log.old
    sudo mkdir -p /var/log
    sudo mount /dev/mapper/vg1-var_log /var/log

    # var_log_audit
    sudo lvcreate -l 100%FREE -n var_log_audit vg1
    sudo mkfs.ext4 /dev/vg1/var_log_audit
    sudo mkdir -p /mnt/var_log_audit
    sudo mount /dev/vg1/var_log_audit /mnt/var_log_audit
    sudo rsync -aulvXpogtr /var/log/audit /mnt/var_log_audit
    sudo rsync -aulvXpogtr /var/log/audit /mnt/var_log_audit
    sudo umount /mnt/var_log_audit
    echo "/dev/vg1/var_log_audit /var/log/audit       ext4    defaults,noatime,nofail 0   2" | sudo tee -a /etc/fstab
    sudo mv /var/log/audit /var_log_audit.old
    sudo mkdir -p /var/log/audit
    sudo mount /dev/mapper/vg1-var_log_audit /var/log/audit

    sudo mount -o remount /var/tmp

    sudo pvcreate /dev/nvme2n1
    sudo vgcreate vg0 /dev/nvme2n1
    #
    sudo lvcreate -l 100%FREE -n home vg0
    sudo mkfs.ext4 /dev/vg0/home
    #
    sudo mkdir -p /mnt/home
    sudo mount /dev/vg0/home /mnt/home
    #
    # sudo shopt -s dotglob
    sudo rsync -aulvXpogtr /home/* /mnt/home
    sudo rsync -aulvXpogtr /home/* /mnt/home
    sudo mv /home /home.old
    #
    # sudo chcon -t var_t /mnt
    #
    sudo umount /mnt/home
    echo "/dev/vg0/home   /home       ext4    defaults,noatime,nofail,nodev 0   2" | sudo tee -a /etc/fstab
    #
    sudo mkdir -p /home
    #
    sudo mount -av
}

function _cis_eks() {
    #statements
    echo "Post boot CIS script for EKS"

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
