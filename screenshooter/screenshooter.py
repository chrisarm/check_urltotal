##
## Version 0.190104
##

from datetime import datetime
import tempfile
import os
import sys
import time
import boto3
from botocore.errorfactory import ClientError
import re
import json
from urllib.request import urlopen
from urllib.parse import urlparse, urlunparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import signal
from contextlib import contextmanager
import traceback
import language_check
import vt_checker

import logging

# Set up logging
debug = 1

# Thresholds
max_errors = 25
MESSAGE_WAIT_TIME = 10
threshold_lang_score = .67 # If score is below this it's likely written poorly which is a sign of phishing
min_lang_score = .2 # If score is below this, it's likely because of too many links, not usually phishing then
VT_POSITIVE_THRESHOLD = 1 #If links in the Virus total report indicate positive for malware, more likely to be bad
website_process_timer = 10 # Time out processing the website after # seconds
Screenshot_Pause = 10 # Time to wait for website to refresh when they detect a bot scraping the site.
chrome_load_time_out = 6
browser_time_out = website_process_timer + Screenshot_Pause  + chrome_load_time_out# Time out grabbing a website after # seconds
LD_Distance = 3 # Used to mark URLs that are close to the "Trusted Domains" but different enought to fool some people
debug_threshold = 1

# S3 Resources
region = 'us-west-2'
screenshot_bucket = 'urltotal-screenshots'
vt_bucket = 'urltotal-vtreports'
results_bucket = 'urltotal-results'
temp_bucket = 'urltotal-tempresults'
s3_client = boto3.client('s3', region_name=region)

# SQS Resources
sqs_client = boto3.client('sqs', region_name=region)
screenshotQueueURL = 'https://sqs.us-west-2.amazonaws.com/815246487488/urlCheckRequests'

sendMailQueue = 'sendmailresults'
sendMailQueueURL = 'https://sqs.us-west-2.amazonaws.com/815246487488/{0}'.format(sendMailQueue)

#TODO 2 Move this logic outside to a separate file and make these grab from the top100 sites. Used to check for similarity to common sites which is a key indicator of malicious phishing
trusted_domains =['google.com', 
    'facebook.com', 
    'microsoft.com', 
    'gmail.com',
    'youtube.com',
    'baidu.com',
    'wikipedia.org',
    'reddit.com',
    'amazon.com',
    'outlook.com',
    'yahoo.com',
    'apple.com',
    'icloud.com',
    'chase.com',
    'wellsfargo.com',
    'usaa.com',
    'sdcc.com',
    'usbank.com',
    'paypal.com',
    'office365.com']

phishy_subjects = ['Password Check Required Immediately',
'You Have A New Voicemail',
'Your order is on the way',
'Change of Password Required Immediately',
'De-activation of [[email]] in Process',
'UPS Label Delivery 1ZBE312TNY00015011',
'Revised Vacation & Sick Time Policy',
'You\'ve received a Document for Signature',
'Spam Notification: 1 New Messages',
'[ACTION REQUIRED] - Potential Acceptable Use Violation',
'You have a new encrypted message',
'IT: Syncing Error - Returned incoming messages',
'HR: Contact information',
'FedEx: Sorry we missed you.',
'Microsoft: Multiple log in attempts',
'IT: IMPORTANT – NEW SERVER BACKUP',
'Wells Fargo: Irregular Activities Detected On Your Credit Card',
'LinkedIn: Your account is at risk!',
'Microsoft/Office 365: [Reminder]: your secured message',
'Coinbase: Your cryptocurrency wallet: Two-factor settings changed']


# Set up logging
logging.basicConfig(level=logging.INFO, filename='URLTotal_Screenshooter.log')

#TODO 3 Add in a way for this to save logs to cloud based storage for easier retrieval when this app is containerized

def print_with_timestamp(*args):
    '''Checks if debug is enabled, then prints and logs the message if it is.'''
    if (debug >= debug_threshold):
        print(str(datetime.utcnow().isoformat()), str(args))
        logging.info(str(datetime.utcnow().isoformat()) + str(args))

print_with_timestamp("Starting to process Queue. Logging is set up.")

class TimeoutException(Exception): pass

@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException('Timed out!')
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    except:
        raise
    finally:
        signal.alarm(0)

def sanitizeUrl(url):
    '''
    Returns a parsed bare URL with non-standard ASCII characters and parameters removed
    Removes all parameters and variables in the URL (Avoiding flagging individual users by visiting sites with their assigned parameters)
    '''
    s_url = url.geturl()
    s_url = re.subn(r'[^-A-Za-z0-9+?&@#/%=~_|:,.\(\)]','',s_url) #Remove crazy non-standard URL characters
    #s_url = re.subn(r'([\|;\&\$\>\<\'\\!>>#]|%3B)','',s_url) #Remove likely cmd injection characters
    s_url = s_url[0].split('?',2)[0] #Remove all parameters
    #TODO2 do something with the second half of s_url which would enable better 
    #tracking of crazy links which are more likely to be spam
    p_url = urlparse(s_url)
    print_with_timestamp('Sanitized URL: {0}'.format(p_url.geturl()))
    return(p_url)


def checkLanguage(flat_email):
    tool = language_check.LanguageTool('en-US')
    errors = tool.check(flat_email)
    return(errors)


def levenshteinDistance(s1, s2):
    '''Retrieved from: https://stackoverflow.com/questions/2460177/edit-distance-in-python
    Answer by "Salvador Dali": https://stackoverflow.com/users/1090562/salvador-dali'''
    if len(s1) > len(s2):
        s1, s2 = s2, s1

    distances = range(len(s1) + 1)
    for i2, c2 in enumerate(s2):
        distances_ = [i2+1]
        for i1, c1 in enumerate(s1):
            if c1 == c2:
                distances_.append(distances[i1])
            else:
                distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
        distances = distances_
    return distances[-1]


def setRecommendations(results):
    try:
        if results['summary'] == 'Seems Safe':
            if len(results['recommendation']) == 0:
                results['recommendation'].append('This email seems to pass all our checks. '
                'If the email is asking for or offering payment, always double check the details and verify  '
                'with a trusted authority whether the intended recipient or sender is valid. This is best done '
                'by calling them directly first. Never provide credit card or account information over normal '
                'email. Use an encrypted email or other secure method of communication instead.'
                )
        else:
            #TODO Get links to specific pages that help users understand how to send money securely for each scenario
            # ie. If users want to use paypal or if they want ot get an escrow account. Make the words link to an
            # appropriate resource to learn about that.
            results['recommendation'].append('<br>This did not pass our checks.<br>'
                'If the email is asking for or offering payment, the sender should prove their identity. '
                'Verify whether the email is authentic by calling or talking to them in person first. '
                'Never provide credit card or account information over normal email. If they request that you ' 
                'send wire payments or account information in an email. Politely request to '
                'use a secure payment portal such as Paypal, a bank escrow account, '
                'or another trusted payment method which allows you to track who received the money '
                'and helps you get the money back if the other party is a fraud.'
                )
        return results
    except Exception as er:
        print_with_timestamp('Had a problem setting the recommendation for the results! {0}'.format(er))
        return results #Not a big deal if recommendation couldn't be set for now. Later it will be a problem
        #TODO 2 Handle exception for recommendations better
        #TODO Make better recommendations based on the summary

# TODO Handle timeout gracefully!
def getScreenshot(parsed_url, browser):
    '''
    Get screenshot of the parsed URL using only the base domain of the URL. 
    Do not want to alert Spammers of indiivdual users by going directly to full 
    paths with parameters and such.
    '''
    if type(parsed_url) != type(urlparse('https://www.google.com')):
        raise TypeError('Wrong Type. Need a "Parsed URL" which will be used to get a screenshot.')

    url = urlunparse(parsed_url)
    n_url = parsed_url.netloc
    if not n_url:
        n_url = parsed_url.path

    # S3 key is the url + png on the end
    filename = '{0}.{1}'.format(n_url,'png')
    #Check if url was screenshot already
    try:
        object_head = s3_client.head_object(Bucket=screenshot_bucket, Key=filename)
        if debug >= debug_threshold + 1:
            print_with_timestamp('S3 check response: {0}'.format(object_head))
        
        if object_head:
        # TODO2 Check object_head for date stamp and get a new screenshot if it's more than a day old
            print_with_timestamp('URL snapshot already done: {0}'.format(filename))
            return(0)
        else:
            print_with_timestamp('New URL. Need to get snapshot. {0}'.format(filename))
    except ClientError as ce:
        print_with_timestamp(ce)
        print_with_timestamp('Must be a new URL. Need to get snapshot. {0}'.format(filename))
    except:
        raise

    # Try and get the website from the parsed URL provided
    try:
        with time_limit(browser_time_out):
            print_with_timestamp('Getting the website ' + n_url)
            browser.get('https://' + n_url)
    except TimeoutException:
        print_with_timestamp('Timed out loading website preview.')
        raise
    except Exception as ne:
        print_with_timestamp('Browser problems! URL: {url}\n{ne}'.format(url=n_url, ne=ne))
        raise

    respS3 = None
    # Try to save a screenshot to S3 time limit is based on # seconds for website to load 
    # plus a pause to allow the page to refresh when it detects a bot.
    #TODO - Figure out how to detect when a website has "detected" a website scraper and is loading the page slowly on purpose.
    try:
        with time_limit(website_process_timer + Screenshot_Pause):
            print_with_timestamp('Creating the screenshot')
            file_path = '/tmp/{0}'.format(filename)
            time.sleep(Screenshot_Pause)
            browser.save_screenshot(file_path)
            if os.stat(file_path).st_size > 12000:
                print_with_timestamp('Saving screenshot to S3')
                respS3 = s3_client.upload_file(
                    file_path, 
                    screenshot_bucket, 
                    filename, 
                    ExtraArgs={'ACL':'public-read',
                        'ContentType':'image/png'
                        }
                    )
            else:
                print_with_timestamp('Screenshot was probably blank since it was so small!')
            os.remove(file_path)
    except TimeoutException:
        print_with_timestamp('Timed out getting screenshot of website preview.')
        raise
    except Exception as ei:
        print_with_timestamp('There was a problem creating a screenshot for the site: {0}'.format(n_url))
        raise

    return(respS3)

def getEmailDomain(email):
    sender_email = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', email)
    if sender_email:
        sender_parts = sender_email[0].split('@',2)
        return(sender_parts[1])
    else:
        return(None)


def getResults(mail_id):
    #Dictionary to pass results to the sender's email address (using zero trust model)
    #Test_results are stored as follows:
    # summary : Overall Determination
    # trust_fwd : DKIM results
    # spam : SES SPAM filter Results
    # virus : SES Virus Scan filter results
    # urls : links used for screenshots of URLs checked in the email. (More or less depending on how it gets used in the future)
    # attachments : Analysis of attachments
    # orginal_text : text based version of the email flattened to do NLP later
    respS3 = None
    try:
        print_with_timestamp('Getting saved results for further processing.')
        temp_file = "/tmp/email_results-{0}.res".format(mail_id)
        respS3 = s3_client.download_file(temp_bucket, mail_id + '.res', temp_file)
    except ClientError as ce:
        print_with_timestamp("Unable to get saved results to process more stuffs: {0}\n{1}".format(respS3,ce))
        raise
    try:
        with open(temp_file, 'r') as file:
            results = json.load(file)
        # Cleanup temp files
        os.remove(temp_file)
    except Exception as ej:
        print_with_timestamp('Could not load JSON results from file. {0}'.format(ej))
        raise
    
    print_with_timestamp("Got Results?: {0}".format(results['summary']))
    return(results)


def saveResults(mail_id, test_results):
    '''
    Saves a "test_results" dictionary to S3 using mail_id as the key
    '''
    temp_file = "/tmp/email_results-{0}".format(mail_id)
    with open(temp_file, 'w+') as file:
            json.dump(test_results, file)

    try:
        response = s3_client.upload_file(temp_file, results_bucket, '{0}.res'.format(mail_id))
    except:
        print_with_timestamp('Error: Unable to upload results to S3! \n{0}'.format(response))
        raise

    os.remove(temp_file)
    return(True)


def sendResults(mail_id):
    '''
    Sends a request to SQS queue for having results emailed back to the original sender
    '''
    data = 'mail_id:{0}'.format(mail_id)
    try:
        print_with_timestamp("Got queue URL {0}".format(sendMailQueue))
        resp = sqs_client.send_message(QueueUrl=sendMailQueueURL, MessageBody=data)
        if debug >= debug_threshold + 1:
            print_with_timestamp("Send result: {0}".format(resp))
    except Exception as e:
        raise Exception("Error: Could not request send mail! {0}".format(e))


def getSQSMessages(queueurl):
    response = sqs_client.receive_message(QueueUrl=queueurl,
            #AttributeNames=['SentTimeStamp'],
            MaxNumberOfMessages=1,
            #MessageAttributeNames=['All'],
            WaitTimeSeconds=MESSAGE_WAIT_TIME)
    if debug >= debug_threshold + 1:
        print_with_timestamp(response)
    try:
        response = response['Messages'][0]
    except KeyError:
        response = None
    except:
        raise
    return(response)


def removeLinks(email_text):
    '''Removes link tags, keeps the text between the tags though.
    <a href="www.google.com">Google</a>  turns into just "Google" '''
    email_text = re.sub(r'\<a .*\>"', '', email_text) # Remove links
    email_text = re.sub(r'\</a\>','',email_text)
    return(email_text)


def main(kargs, perpetual = False):
    messages = None

    #Browser settings
    chromedriver = '/usr/bin/chromedriver'
    options = Options()
    options.headless=True
    options.binary_location = 'headless-chrome/headless_shell'
    options.add_argument('window-size=1280x960')

    if len(kargs) == 2 and kargs[1] == 'Perpetual':
        perpetual = True

    # Only check once for messages unless we're in "perpetual" check mode
    if perpetual == True:
        while messages == None:
            messages = getSQSMessages(screenshotQueueURL)
    else:
        messages = getSQSMessages(screenshotQueueURL)

    if messages == None or len(messages) == 0:
        return(perpetual)

    if debug >= debug_threshold + 1:
        print_with_timestamp('!! Messages: {0}'.format(messages))

    data = messages['Body']

    # Take the mail ID from the beginning of the message data and remove quotes from each side
    mail_id = data.split(':',1)[0]
    print_with_timestamp('Mail ID: {0}'.format(mail_id))

    if debug >= 2:
        print_with_timestamp(data)

    receipt_handle = messages['ReceiptHandle']
    try:
        results = getResults(mail_id)
    except Exception as em:
        # Delete the sqs message since it had something wrong with it.
        del_response = sqs_client.delete_message(QueueUrl=screenshotQueueURL, ReceiptHandle=receipt_handle)
        print_with_timestamp('Problem getting Results. Message deleted from Queue: {del1}. {em1}'.format(del1=del_response, em1=em))
        raise(em)

    # Determine the language score
    flat_email = removeLinks(results['forwarded_email'])
    
    if debug >=2:
        print_with_timestamp('Email without links: \n{0}'.format(flat_email))
    language_score = 0
    try:
        email_errors = checkLanguage(flat_email)
        num_errors = len(email_errors)
        num_words = len(flat_email.split())
        language_score = max(1-(num_errors/num_words),0)

        print_with_timestamp('Language Score: {0}'.format(language_score))
        results['language_score'] = '{:.2%}'.format(language_score)
    except Exception as el:
        print_with_timestamp('Unable to check spelling and grammar! {0}'.format(el))
        results['language_score'] = '0%'
        language_score = 0
        #Keep going... not a big deal

    # Parse out the URLS and VT Resource Links
    urls = data[data.find('urls')+7:data.find('vt_resources')-3]
    vt_resources = data[data.find('vt_resources')+14:-1]

    urls = re.subn(r'[\[\]\'\{\} ]','',urls)[0].split(',') #Parse text with URLs into a list
    vt_resources = re.subn(r'[\[\]\'\{\} ]','',vt_resources)[0].split(',') # Parse text with Virus Total Scan IDs into a list

    print_with_timestamp('VT Resources: {0}'.format(vt_resources))
    print_with_timestamp('URLs: {0}'.format(urls))


    # Do some levenshteinDistance checks on URLS
    for url in urls:
        url = urlparse(url).netloc.split('.')
        if len(url) > 2:
            url = url[-2] + '.' + url[-1]
        ld_urls = [td for td in trusted_domains if levenshteinDistance(url,td) < LD_Distance]
    
    vtindex = 0
    print_with_timestamp('Trying to get Virus Total Reports.')
    for vt_resource in vt_resources:
        vt_resource = urlparse(vt_resource)
        
        if vt_resource.netloc == '' or vt_resource == None:
            print_with_timestamp('Invalid URL for VT resource! Skipping VT.')
            continue

        #Generate path for saving the results using the netloc of the URL
        path = vt_resource.netloc
        path_len = len(path)
        if path[-1:] != '/': #Add in a forward slash if the url doesn't have it.
            path = path + '/'
        print_with_timestamp('VT Resource Net Location: {0}'.format(path))

        reportFilename = 'report-{0}'.format(vtindex)
        s3Path = path + reportFilename

        object_list = s3_client.list_objects(Bucket=vt_bucket, Prefix=s3Path)
        resp = object_list.get(s3Path)
        print_with_timestamp('S3 vt check response: {0}'.format(resp))
        if resp == None:
            vtreport = vt_checker.getVirusTotalReport(vt_resource.geturl())
        else:
            #TODO 2 Set up to get from S3 bucket
            # vtreport = s3_client.download_file(Bucket=vt_bucket, Prefix=s3Path)
            # Temp Fix
            vtreport = vt_checker.getVirusTotalReport(vt_resource.geturl())

        if vtreport:
            print_with_timestamp('Virus Total report: '.format(vtreport))
            file_path = '/tmp/{0}.rep'.format(reportFilename)
            try:
                #Save Virus Total Report as a JSON formatted file
                with open(file_path, 'w+') as file:
                    json.dump(vtreport, file) 
                
                #Upload it to S3
                s3_client.upload_file(file_path, vt_bucket, s3Path)
                print_with_timestamp('VT Results uploaded. {0}'.format(s3Path))

                #Enable follow-on retrieval through vt_results list
                if 'positives' in vtreport:
                    if vtreport['positives'] > 0:
                        results['vt_results'][str(vtindex)] = (vtreport['positives'],s3Path)
                    print_with_timestamp('Num of positive results in VT Report: {0}'.format(vtreport['positives']))
                vtindex += 1
                os.remove(file_path)
            except:
                print_with_timestamp('Problem saving VT Reports.')
                raise

    try:
        browser = webdriver.Chrome(executable_path=chromedriver, options=options,)
        urlIndex = 0
    except Exception as eb:
        print_with_timestamp('There was a problem with creating the browsing session. {0}'.format(eb))
        perpetual = False
        raise

    vt_positives = len(results['vt_results'])
    print_with_timestamp('Virus Total Results Length: {0}'.format(vt_positives))

    #Only get screenshots if VT Results came back with mostly good URLs, else don't go there!
    if vt_positives <= VT_POSITIVE_THRESHOLD: 
        try:
            for url in urls:
                print_with_timestamp("URL: {0}".format(url))
                url = urlparse(url)
                p_url = sanitizeUrl(url)
                if p_url.netloc:
                    p_net = p_url.netloc
                else:
                    p_net = p_url.path
                if p_net:
                    try:
                        respShot = getScreenshot(p_url, browser) #Make sure to pass parsed URL object to getScreenshot
                    except TimeoutException:
                        print_with_timestamp('Site took too long to load, no screenshot taken!')
                        continue
                    except:
                        print_with_timestamp('Deleting the queue message since browser session failed with an unknown error.')
                        sqs_client.delete_message(QueueUrl=screenshotQueueURL, ReceiptHandle=receipt_handle)
                        raise
                    if respShot != 0:
                        print_with_timestamp('Response for Screenshot: {0}'.format(respShot))
                        urlIndex += 1 #Increment only after assigning a screenshot to that index
                else:
                    # TODO 1 Figure out why this is getting hit. No invalid URL should make it this far.
                    print_with_timestamp("URL net location was not valid. Skipping screenshot: {0}".format(p_net))
            browser.quit() #Quit the browser after grabbing all the screenshots for the site in question
        except Exception as eu:
            print_with_timestamp('Could not get all the screenshots. {0}'.format(eu))
            print_with_timestamp(traceback.print_stack())
            raise

            ''' TODO 3: If this raises a browser error check if more than one instance is running,
            # and if only this one is running, start a new EC2 instance. Then terminate this one immediately.
            # The goal is to prevent the rest of the AWS resources from being fully compromised due to a
            # compromised browser.'''
    
    # Set the summary
    else: #Set summary first for VT scans that had positive results 
        try:
            if results['summary'] == 'Seems Safe':
                results['summary'] ='Smells Phishy - Failed Virus Total checks'
                results['recommendation'].append('At least one URL in the email has been reported as malicious'
                    'by more than {threshold} trusted sources.'.format(threshold=VT_POSITIVE_THRESHOLD))
            else:
                results['recommendation'].append('This email failed for multiple reasons.'
                    'At least one URL in the email has been reported as malicious'
                    'by more than {threshold} trusted sources.'.format(threshold=VT_POSITIVE_THRESHOLD))
        except:
            print_with_timestamp('Had an issue setting the summary for number of positives.')
            raise

    #Set up to check if domain of forwarded email is the same as the one that is checking for phishing
    forwarded_email_domain = getEmailDomain(results['forwarded_email_from'])
    forwarder_domain = getEmailDomain(results['fwd_sender'])

    # What to do if everything Seems Safe?! ...Check for social engineering bullshit
    if results['summary'] == 'Seems Safe':
        #Do they suck at english?
        if (language_score < threshold_lang_score and language_score > min_lang_score) or language_score < 0:
            results['recommendation'].append('Poor spelling and grammar are a red flag for possible phishing. ')

            #Check to see if domain of the forwarded email is the same as the person checking for phishing
            if forwarded_email_domain == forwarder_domain:
                results['summary'] = 'Seems Safe - Failed the Spelling and Grammar Test'
                results['recommendation'].append('Since the email came from the same domain as yours, it is less likely '
                    'to be phishing, but verify with the sender before making any payments. ')
            else:
                results['summary'] = 'Smells Phishy - Failed the Spelling and Grammar Test'
                results['recommendation'].append('A strange sender with bad grammar is more likely to be malicious than one with good grammar. '
                    'Spelling and grammar are just one indicator though. Be very careful and double check '
                    'the authenticity of the email before making any payments or sending sensitive information!' )
        #Are they using KnowB4? (Phishy Subjects are top 10 from KnowB4)
        if results['subject'] in phishy_subjects:
            results['summary'] = 'Smells Phishy - Common Subject Line for Phishing'
            results['recommendation'].append('Phishing scams often reuse the same subject lines. '
                'Looks like the subject line for this email matched with ones used in common scams.' )
    #Are they trying to imitate a common URL?
    if len(ld_urls) >= 1:
        results['summary'] = 'Smells Phishy - Links imilar to {ld} may be fake'.format(ld=ld_urls[0])
        results['recommendation'].append('Phishing scams may alter links and domain names slightly so that '
            'people will click on the links without realizing that they are going to a fake site. Once they '
            'get users to visit the fake site and enter in passwords or information, hackers are able to '
            'steal the password and make it seem like the user just typed it in the real one.')
        
    # If things aren't safe, but the domain is the same... then time to raise a rukus
    else:
        if forwarded_email_domain == forwarder_domain:
            results['recommendation'].append('Since the email came from the same domain as yours, inform your IT '
                'Team that the email failed these tests. They can provide further assistance '
                'and help mitigate additional problems if the email is in fact phishing. ')

    results = setRecommendations(results)

    # Save the results
    if debug >= debug_threshold + 1:
        print_with_timestamp('All Results: {0}'.format(results))
    saveResults(mail_id, results)

    # Message processed completely, and sendResults requested, now delete SQS message that started this
    del_response = sqs_client.delete_message(QueueUrl=screenshotQueueURL, ReceiptHandle=receipt_handle)

    return(perpetual)

if __name__ == '__main__':
    perpetual = True
    errors = 0
    while perpetual:
        try:
            perpetual = main(sys.argv, perpetual) # main returns value indicating if it should be run again
            #if perpetual comes back as false or if there's an error.
        except Exception as e:
            errors += 1
            print_with_timestamp('There was an issue! {exception}\nError count:{errors}'.format(exception=e,errors=errors))
            if errors <= max_errors:
                pass
            else:
                raise ValueError("Too many errors!")

#Found multiproccessor code here: https://stackoverflow.com/questions/366682/how-to-limit-execution-time-of-a-function-call-in-python
