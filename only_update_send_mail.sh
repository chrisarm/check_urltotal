#!/bin/bash
cwd0=$(pwd)
cd /home/chris/Dropbox/0-AI/urltotal/mail_handler
zip -g /home/chris/Dropbox/0-AI/urltotal/mail_handler.zip email_handler.py
aws lambda update-function-code --zip-file 'fileb:///home/chris/Dropbox/0-AI/urltotal/mail_handler.zip' --function-name mail_handler
cd $cwd0
