#!/usr/bin/env bash
until pvcreate /dev/nvme2n1
do
  echo "Waiting till EBS volume is up"
  sleep 2
done
vgcreate vg1 /dev/nvme2n1
# var
lvcreate -l 60%FREE -n var vg1
mkfs.ext4 /dev/vg1/var
mkdir -p /mnt/var
mount /dev/vg1/var /mnt/var
shopt -s dotglob
rsync -aulvXpogtr /var/* /mnt/var
rsync -aulvXpogtr /var/* /mnt/var
chcon -t var_t /mnt/var
umount /mnt/var
echo "/dev/vg1/var   /var       ext4    defaults,noatime,nofail 0   2" | tee -a /etc/fstab
mv /var /var.old
mkdir -p /var
mount /dev/mapper/vg1-var /var
# var_tmp
lvcreate -l 33%FREE -n var_tmp vg1
mkfs.ext4 /dev/vg1/var_tmp
mkdir -p /mnt/var_tmp
mount /dev/vg1/var_tmp /mnt/var_tmp
shopt -s dotglob
rsync -aulvXpogtr /var/tmp/* /mnt/var_tmp
rsync -aulvXpogtr /var/tmp/* /mnt/var_tmp
chcon -t tmp_t /mnt/var_tmp
umount /mnt/var_tmp
echo "/dev/vg1/var_tmp   /var/tmp       ext4    defaults,noatime,nofail,noexec,nodev,nosuid 0   2" | tee -a /etc/fstab
mv /var/tmp /var_tmp.old
mkdir -p /var/tmp
mount /dev/mapper/vg1-var_tmp /var/tmp
# var_log
lvcreate -l 50%FREE -n var_log vg1
mkfs.ext4 /dev/vg1/var_log
mkdir -p /mnt/var_log
mount /dev/vg1/var_log /mnt/var_log
shopt -s dotglob
rsync -aulvXpogtr /var/log/* /mnt/var_log
rsync -aulvXpogtr /var/log/* /mnt/var_log
chcon -t var_log_t /mnt/var_log
umount /mnt/var_log
echo "/dev/vg1/var_log   /var/log       ext4    defaults,noatime,nofail 0   2" | tee -a /etc/fstab
mv /var/log /var_log.old
mkdir -p /var/log
mount /dev/mapper/vg1-var_log /var/log
# var_log_audit
lvcreate -l 100%FREE -n var_log_audit vg1
mkfs.ext4 /dev/vg1/var_log_audit
mkdir -p /mnt/var_log_audit
mount /dev/vg1/var_log_audit /mnt/var_log_audit
shopt -s dotglob
rsync -aulvXpogtr /var/log/audit /mnt/var_log_audit
rsync -aulvXpogtr /var/log/audit /mnt/var_log_audit
chcon -t auditd_log_t /mnt/var_log_audit
umount /mnt/var_log_audit
echo "/dev/vg1/var_log_audit /var/log/audit       ext4    defaults,noatime,nofail 0   2" | tee -a /etc/fstab
mv /var/log/audit /var_log_audit.old
mkdir -p /var/log/audit
mount /dev/mapper/vg1-var_log_audit /var/log/audit
