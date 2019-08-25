from datetime import datetime
import requests
import json
import boto3
import time

vt_domain_report = 'https://www.virustotal.com/vtapi/v2/url/report'
vt_api_key='f92227f9575ba7dabc3ef3b83b7a8ec3840609dbdba0b9561b88b4e2e273f96d'

#Helps limit the processing power used to verify email data
max_links_to_check = 1
debug_threshold = 1

#Helps limit the processing power used to verify email data
debug_threshold = 1
debug = 1
max_attempts = 2
wait_between_attempts = 20

#Checks if debug is enabled, then print the message if it is.
def print_with_timestamp(*args):
    if (debug >= debug_threshold):
        print(datetime.utcnow().isoformat(), *args)

def getVirusTotalReport(resource):
    '''
    Returns the JSON output format from the Virus Total Report results given a resource URL that was previously submitted for a report
    '''
    try:
        #####TODO TODO TODO: figure out how to read the response from the url scan request to VT so sI can pull down the report later.
        ### Plan to save the url request in an s3 bucket same as the screenshots using the url as the key for the object
        attempts = 0
        params = {'apikey':vt_api_key, 'resource':resource}
        while attempts < max_attempts:
            report = requests.get(vt_domain_report, params=params)
            
            if debug >= 2:
                print_with_timestamp('Virus Total Response: {0}'.format(report.json()))
            
            if report.status_code == 200:
                print_with_timestamp('Returning VT Results JSON.')
                return(report.json())
            else:
                raise ValueError('Status Code from VT Report was not expected.\n {0}'.format(report.json()))
            
            attempts += 1
            time.sleep(wait_between_attempts)
        return(None)
    except Exception as e:
        print_with_timestamp('Unable to get VT response: {0}'.format(e))