from datetime import datetime
from botocore.errorfactory import ClientError
from urllib.parse import urlparse
import json
import tempfile
import os
import boto3
import re

region = os.environ['REGION']
sender = os.environ['SENDER']
debug = int(os.environ['DEBUG_LEVEL'])

# S3 Resources
feedback_bucket = 'urltotal-feedback'
s3_client = boto3.client('s3', region_name=region)

debug_threshold = 1

#Checks if debug is enabled, then print the message if it is.
def print_with_timestamp(*args):
    if (debug >= debug_threshold):
        print(datetime.utcnow().isoformat(), *args)


def send_result(event, context):
	# Accept HTTP Post event
	# Check parameters for valid mail ID
	# Ensure that mail ID hasn't been used before by retrieving S3 object in urltotal-feedback bucket
	# See if object has "Feedback Received" text and if true, quit
	# If object doesn't have feedback received, parse the post event details
	# Update the s3 object to say Feedback Received and send 1 sec redirect URL to force user's browser to refresh.