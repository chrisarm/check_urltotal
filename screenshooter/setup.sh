aws s3 cp s3://screenshooter/google-chrome-stable_current_x86_64.rpm /home/ec2-user/google-chrome-stable_current_x86_64.rpm
mkdir /home/ec2-user/screenshooter

aws s3 cp s3://screenshooter/screenshooter.zip /home/ec2-user/screenshooter/screenshooter.zip
aws s3 cp s3://screenshooter/google-chrome-stable_current_x86_64.rpm /home/ec2-user/
unzip /home/ec2-user/screenshooter/screenshooter.zip 
cd /home/ec2-user/screenshooter

yum install -y /home/ec2-user/google-chrome-stable_current_x86_64.rpm
yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm python3-pip.noarch fontconfig chromedriver

#LanguageTool Server
yum install git default-jdk maven
git clone https://github.com/languagetool-org/languagetool.git
./build.sh languagetool-standalone clean package -DskipTests