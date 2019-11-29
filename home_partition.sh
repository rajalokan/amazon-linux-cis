#!/usr/bin/env bash
until pvcreate /dev/nvme1n1
do
  echo "Waiting till EBS volume is up"
  sleep 2
done
vgcreate vg0 /dev/nvme1n1
#
lvcreate -l 100%FREE -n home vg0
mkfs.ext4 /dev/vg0/home
mkdir -p /mnt/home
sudo mount /dev/vg0/home /mnt/home
sudo shopt -s dotglob
sudo rsync -aulvXpogtr /home/* /mnt/home
sudo rsync -aulvXpogtr /home/* /mnt/home
sudo chcon -t home_root_t /mnt/home
sudo umount /mnt/home
echo "/dev/vg0/home   /home       ext4    defaults,noatime,nofail,nodev 0   2" | tee -a /etc/fstab
mv /home /home.old
mkdir /home
mount -av
