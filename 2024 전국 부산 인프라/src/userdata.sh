#!/bin/bash
yum update -y
yum install -y jq curl wget git
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
ln -s /usr/local/bin/aws /usr/bin/
ln -s /usr/local/bin/aws_completer /usr/bin/
dnf install -y mariadb105
sed -i "s|PasswordAuthentication no|PasswordAuthentication yes|g" /etc/ssh/sshd_config
echo "Port 2222" >> /etc/ssh/sshd_config
systemctl restart sshd
echo 'Skills2024**' | passwd --stdin ec2-user
echo 'Skills2024**' | passwd --stdin root

cat <<\EOF>> ~/.bashrc
trap ". $HOME/.logout.sh; exit" 0

#!/bin/bash
USERNAME=$(whoami)
TIME=$(date -d "+9 hours" "+%Y-%m-%d %H:%M:%S")
TIMESTAMP=$(($(date +%s%N)/1000000))
set +H
LOGIN_FORMAT="{ ${USERNAME}, ${USERNAME} has logged in!, ${TIME} }"
aws logs put-log-events --log-group-name wsi-bastion-user-logs --log-stream-name wsi-bastion-stream --log-events "[{\"timestamp\": $TIMESTAMP, \"message\": \"$LOGIN_FORMAT\"}]" > /dev/null
EOF

cat <<\EOF>> /home/ec2-user/.bashrc
trap ". $HOME/.logout.sh; exit" 0

#!/bin/bash
USERNAME=$(whoami)
TIME=$(date -d "+9 hours" "+%Y-%m-%d %H:%M:%S")
TIMESTAMP=$(($(date +%s%N)/1000000))
set +H
LOGIN_FORMAT="{ ${USERNAME}, ${USERNAME} has logged in!, ${TIME} }"
aws logs put-log-events --log-group-name wsi-bastion-user-logs --log-stream-name wsi-bastion-stream --log-events "[{\"timestamp\": $TIMESTAMP, \"message\": \"$LOGIN_FORMAT\"}]" > /dev/null
EOF

source ~/.bashrc
soure /home/ec2-user/.bashrc

cat <<\EOF>> ~/.logout.sh
#!/bin/bash
USERNAME=$(whoami)
TIME=$(date -d "+9 hours" "+%Y-%m-%d %H:%M:%S")
TIMESTAMP=$(($(date +%s%N)/1000000))
set +H
LOGIN_FORMAT="{ ${USERNAME}, ${USERNAME} has logged out!, ${TIME} }"
aws logs put-log-events --log-group-name wsi-bastion-user-logs --log-stream-name wsi-bastion-stream --log-events "[{\"timestamp\": $TIMESTAMP, \"message\": \"$LOGIN_FORMAT\"}]" > /dev/null
EOF

cat <<\EOF>> /home/ec2-user/.logout.sh
#!/bin/bash
USERNAME=$(whoami)
TIME=$(date -d "+9 hours" "+%Y-%m-%d %H:%M:%S")
TIMESTAMP=$(($(date +%s%N)/1000000))
set +H
LOGIN_FORMAT="{ ${USERNAME}, ${USERNAME} has logged out!, ${TIME} }"
aws logs put-log-events --log-group-name wsi-bastion-user-logs --log-stream-name wsi-bastion-stream --log-events "[{\"timestamp\": $TIMESTAMP, \"message\": \"$LOGIN_FORMAT\"}]" > /dev/null
EOF


chmod +x ~/.logout.sh
chmod +x /home/ec2-user/.logout.sh