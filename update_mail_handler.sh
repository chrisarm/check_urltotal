#!/bin/bash
cwd0=$(pwd)
cd /home/chris/Dropbox/0-AI/urltotal/mail_handler
zip -g /home/chris/Dropbox/0-AI/urltotal/mail_handler.zip email_handler.py
aws lambda update-function-code --zip-file 'fileb:///home/chris/Dropbox/0-AI/urltotal/mail_handler.zip' --function-name mail_handler
aws lambda invoke --invocation-type RequestResponse --function-name mail_handler --region us-west-2 --log-type Tail --payload 'file:///home/chris/Dropbox/0-AI/urltotal/mail_handler/lambda_test.json' mail_handler.txt | grep LogResult | awk -F" " '{print $2}' | sed 's/\"//g' | sed 's/,//g' | base64 --decode
cd $cwd0
