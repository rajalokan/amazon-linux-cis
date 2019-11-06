#!/usr/bin/env bash

# 1.2.3
mongo_repo_path="/etc/yum.repos.d/mongodb-org-4.0.repo"
[[ -f $mongo_repo_path ]] && sudo sed -i 's/^gpgcheck=0$/gpgcheck=1/' $mongo_repo_path

# 4.2.4
sudo find /var/log -type f -exec chmod g-wx,o-rwx {} +
sudo find /var/log -type d -exec chmod g-wx,o-rwx {} +
sudo chmod 755 /var/log

# 5.2.15
sudo tee -a /etc/ssh/sshd_config > /dev/null << EOF
#
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
EOF
