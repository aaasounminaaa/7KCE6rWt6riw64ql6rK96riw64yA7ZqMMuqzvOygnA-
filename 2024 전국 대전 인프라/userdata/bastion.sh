#!/bin/bash
echo 'skills2024' | passwd --stdin ec2-user
sed -i 's|.*PasswordAuthentication.*|PasswordAuthentication yes|g' /etc/ssh/sshd_config
systemctl restart sshd