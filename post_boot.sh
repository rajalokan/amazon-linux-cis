#!/usr/bin/env bash

function _cis_mongo() {
    #statements
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

    # 3.5.1.4
    # TODO: Not working
    # sudo netstat -ln
    sudo iptables -A INPUT -p tcp --destination-port 27017 -m state --state NEW,ESTABLISHED -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --source-port 27017 -m state --state ESTABLISHED -j ACCEPT

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
