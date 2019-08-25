from datetime import datetime, timedelta
import time
from email.parser import BytesParser
from email import policy
import json
import tempfile
import os
import boto3
from boto3.dynamodb.conditions import Key, Attr
import re
from urllib.request import urlopen
from urllib.parse import urlparse
import requests
import random
import mimetypes

vt_api_key = os.environ['VirusTotalAPIKey']
bucket_region = os.environ['REGION']
sender = os.environ['SENDER']
secretID = os.environ['SECRET_ID']
check_secret = int(os.environ['CHECK_SECRET'])
debug = int(os.environ['DEBUG_LEVEL'])
#delete_emails = int(os.environ['DELETE_EMAILS'])

#TODO2 Move this logic outside to a separate file and make these grab from the top100 sites. Used to check for similarity to common sites which is a key indicator of malicious phishing
trusted_domains = ['google.com', 
    'facebook.com', 
    'microsoft.com', 
    'gmail.com',
    'youtube.com',
    'baidu.com',
    'wikipedia.org',
    'reddit.com',
    'qq.com',
    'amazon.com',
    'outlook.com',
    'yahoo.com',
    'aol.com',
    'apple.com',
    'icloud.com']

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

vt_domain_scan = 'https://www.virustotal.com/vtapi/v2/url/scan'

#Set up datetime variables for verifying send limits
nowDT = datetime.utcnow()
nowDTiso = nowDT.isoformat()

#Helps limit the processing time used to verify email data
max_links_to_check = 2
debug_threshold = 1

#Authorization limits
max_email_checks = 5

# S3 Resources
s3_client = boto3.client('s3', region_name=bucket_region)

# SES Resources
ses_client = boto3.client('ses')

# DynamoDB Resources
ddb = boto3.resource('dynamodb')
email_table = ddb.Table('emailContext') #Table contains information on every email addressed used as the forward source and expiration datetime

# SQS Resources
sqs_client = boto3.client('sqs')
checkURLQueue = 'urlCheckRequests'
screenshotQueueURL = 'https://sqs.us-west-2.amazonaws.com/815246487488/{0}'.format(checkURLQueue)


#Checks if debug is enabled, then print the message if it is.
def print_with_timestamp(*args):
    if (debug >= debug_threshold): 
        print(datetime.utcnow().isoformat(), *args)


def sanitizeUrl(url, removeParams = True, removeSubDirs = True):
    '''
    Returns a parsed bare URL with non-standard ASCII characters and parameters removed
    Removes all parameters and variables in the URL 
    (Need to try and avoid flagging individual users by visiting sites with their assigned parameters)
    '''
    s_url = re.subn(r'[^-A-Za-z0-9+?&@#/=~_!:,.\(\)]','',url) #Remove crazy non-standard URL characters
    if removeParams:
        s_url = s_url[0].split('?',2)[0] #Remove parameters

    if removeSubDirs:
        #Split based on '/' then join the first few parts 
        splits = s_url.split('/')
        s_url = '/'.join(splits[:3])+'/'
    # TODO2 do something with the second half of s_url which would enable better 
    # tracking of crazy links which are more likely to be spam
    p_url = urlparse(s_url)
    if debug >= 2:
        print_with_timestamp('Sanitized URL: {0}'.format(p_url.geturl()))
    return(p_url)


# Grabs an email saved in S3 by SES
def getS3email(bucket, mail_ID):
    print_with_timestamp('Trying to get file from: {0}/{1}'.format(bucket, mail_ID))
    temp_file = '/tmp/email_file'
    s3_client.download_file(bucket, mail_ID, temp_file)
    print_with_timestamp('File with email message downloaded!')
    with open(temp_file, 'rb') as email_msg:
        email_message = BytesParser(policy = policy.default).parse(email_msg)
        print_with_timestamp('Found email to proccess: \n{0}'.format(email_message['subject']))

        #Delete the file!
        os.remove(temp_file)
        return(email_message)


def getEmailContext(email):
    '''
    Queries the noSQL DB to see whether the email sender is recognized and to get related limits
    If no sender found then return None
    '''
    print_with_timestamp('Getting info from DB for {0}'.format(email))
    sender_email = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', email)
    sender_parts = sender_email[0].split('@',2)
    
    email_name = sender_parts[0]
    domain_name = sender_parts[1]

    #TODO 2 Save row in 

    if sender_email == None:
        raise ValueError('Not a valid email sender address')
    else:
        response = email_table.query(
            KeyConditionExpression=Key('domain').eq(domain_name)
        )
        
        #TODO3 Make sure the response has all the results DynamoDB only gives 1MB at a time! For now though it's not a problem
        
        if debug > 2:
            print_with_timestamp('DB Response: {0}'.format(response))
        
        items = response['Items']
        if items == []:
            return(None)
        else:
            for item in items:
                print_with_timestamp(item)
                if item['email'] == email_name:
                    print_with_timestamp('Found email address in the results')
                    # Convert text from DB item into actual datetime objects
                    try:
                        firstDT = item['firstSendDT'].split('.',2)[0]
                        resetDT = item['resetAfterDT'].split('.',2)[0]
                        lastDT =  item['lastDT'].split('.',2)[0]
                        expireDT = item['expireDT'].split('.',2)[0]

                        firstDT = datetime.strptime(firstDT, '%Y-%m-%dT%H:%M:%S')
                        resetDT = datetime.strptime(resetDT, '%Y-%m-%dT%H:%M:%S')
                        lastDT = datetime.strptime(lastDT, '%Y-%m-%dT%H:%M:%S')
                        expireDT = datetime.strptime(expireDT, '%Y-%m-%dT%H:%M:%S')

                        item['firstSendDT'] = firstDT
                        item['resetAfterDT'] = resetDT
                        item['lastDT'] = lastDT
                        item['expireDT'] = expireDT
                    except Exception as ec:
                        print_with_timestamp('Could not convert email context items to the right types. {0}', ec)
                        raise
                    
                    try:
                        totalSent = item['totalSent']
                    except KeyError:
                        item['totalSent'] = 1
                        
                    return(item)
            print_with_timestamp('Could not find the email address in the results')
            return(None)


def updateEmailContext(email, domain, limitType='perDay', sendLimit=5, limitCount=1, totalSent=1, resetDT=nowDT, firstDT=nowDT, expireDT=nowDT):
    sender_parts = None
    firstDTiso = ''
    resetDTiso = ''
    expireDTiso = ''

    #Set any empty input values as appropriate
    if firstDT == '' or firstDT == None:
        firstDT = nowDT

    if resetDT == '' or resetDT == None or resetDT == nowDT:
        resetDT = (nowDT+timedelta(days=1))
    
    if expireDT == '' or expireDT == None or expireDT == nowDT:
        expireDT = (nowDT+timedelta(days=365))

    # #Make sure all dates are ISO format
    if type(firstDT) == type(nowDT):
        firstDTiso = firstDT.isoformat()

    if type(resetDT) == type(nowDT):
        resetDTiso = resetDT.isoformat()

    if type(expireDT) == type(nowDT):
        expireDTiso = expireDT.isoformat()

    try:
        response = email_table.update_item(
            Key={
                'domain': domain,
                'email': email
            },
            UpdateExpression='SET limitType= :l1, sendLimit= :l2, limitCount= :l3, totalSent= :l4, resetAfterDT= :l5, firstSendDT= :l6, lastDT= :l7, expireDT= :l8',
            ExpressionAttributeValues={
                ':l1':limitType,
                ':l2':sendLimit,
                ':l3':limitCount,
                ':l4':totalSent,
                ':l5':resetDTiso,
                ':l6':firstDTiso,
                ':l7':nowDTiso,
                ':l8':expireDTiso
            },
            ReturnValues='UPDATED_NEW'
        )
        if debug >= 2:
            print_with_timestamp(response)
    except Exception as edb:
        print_with_timestamp(edb)
        raise

    print_with_timestamp('Updated db item: {0}'.format(response))
    if response != None:
        return response['Attributes']
    else:
        return None


def newEmailContext(email, domain, limitType='perDay', sendLimit=max_email_checks, limitCount=1, firstDT='', resetDT='', expireDT=''):
    sender_parts = None

    firstDTiso = ''
    resetDTiso = ''
    expireDTiso = ''
    totalSent = 0

    #Set any empty input values as appropriate
    if firstDT == '' or firstDT == None:
        firstDT = nowDT
    
    if resetDT == '' or resetDT == None or resetDT == nowDT:
        resetDT = (nowDT+timedelta(days=1))
    
    if expireDT == '' or expireDT == None or expireDT == nowDT:
        expireDT = (nowDT+timedelta(days=365))

    # #Make sure all dates are ISO format
    if type(firstDT) == type(nowDT):
        firstDTiso = firstDT.isoformat()

    if type(resetDT) == type(nowDT):
        resetDTiso = resetDT.isoformat()

    if type(expireDT) == type(nowDT):
        expireDTiso = expireDT.isoformat()

    try:
        response = email_table.put_item(
            Item={
                'domain': domain,
                'email': email,
                'limitType': limitType,
                'sendLimit': sendLimit,
                'limitCount': 1,
                'totalSent': 1,
                'resetAfterDT': resetDTiso,
                'firstSendDT': firstDTiso,
                'lastDT': nowDTiso,
                'expireDT': expireDTiso
            }
        )
        if debug >= 2:
            print_with_timestamp(response)
    except Exception as epb:
        print_with_timestamp(epb)
        raise

    print_with_timestamp('DB item added: {0}'.format(response))
    if response != None:
        return response
    else:
        return None


def getAttachmentTypes(email):
    '''
    Iterates through attachments of the email until a possible executable attachment is found
    '''
    if debug >= debug_threshold + 1:
        print_with_timestamp('Getting dictionary of attachment types from email:\n\t{0}'.format(email))

    types = {'attachment-0':{'mime_match':False,'Executable':False,'MS Office':False,'PDF':False}}
    executableExtensions = set(['exe', 'dmg', 'deb', 'sh'])
    pdfExtensions = set(['pdf','PDF'])
    msofficeExtentions = set(['doc','docx','dot','dotx','dotm,''xls','xlsx','ppt','pptx','acccdb'])

    attachmentIndex = 0
    for attachment in email.iter_attachments():
        filename = attachment.get_filename()
        extension = filename[-3:]
        if filename:
            extension = os.path.splitext(filename)[1]
        
        # Check to see if the attachment matches the type guessed in the email. Mismatch isn't bad necessarily.
        # Just one more data point indicating whether an email is phishy or not
        extensionTest = mimetypes.guess_extension(attachment.get_content_type())
        if extension == extensionTest:
            types['attachments-{0}'.format(attachmentIndex)]['mime_match'] = True

        if extension in executableExtensions:
            print_with_timestamp('Found an executable file attachment!')
            types['attachments-{0}'.format(attachmentIndex)]['Executable']=True
        elif extension == pdfExtensions:
            print_with_timestamp('Found a PDF file attachment!')
            types['attachments-{0}'.format(attachmentIndex)]['PDF']=True
        elif extension in msofficeExtentions:
            print_with_timestamp('Found a PDF file attachment!')
            types['attachments-{0}'.format(attachmentIndex)]['PDF']=True
        
        attachmentIndex += 1
    print_with_timestamp('No executable files found.')
    return (types)


def isAuthorized(email_context):
    '''
    Provide a dictionary with the following values {
        'domain':'domain of the email used to forward the suspicious email'
        'email':'email name of the address that forwarded the suspicious email'
        'limitType':'Whether the limit type is time based to total emails'
        'sendLimit':'The max or limit allowed for the limitType'
        'limitCount':'The number of times hit during the current counter'
        'resetAfterDT':'When the limit count gets reset, should be based on the first hit for the current period of time'
    }
    Returns a True/False determination as well as the DB response after checking against blacklists and validating limits
    '''
    print_with_timestamp('Checking if authorized')
    if email_context == None:
        return(False, email_context)
    
    resetDT = email_context['resetAfterDT']
    origReset = resetDT
    
    # Increment the limitCount and totalSent
    limit_count = email_context['limitCount'] + 1
    total_sent = email_context['totalSent'] + 1
    reset_passed = False
    
    # Check if limit exists or when limit resets and reset if necessary
    if email_context['limitType'] == 'noLimit':
        limit_count = 0
        send_limit = 1000
    elif resetDT <= nowDT:
        print_with_timestamp('Reset Time!')
        reset_passed = True
        limit_count = 1

    # Check if limit is exceeded
    if limit_count > int(email_context['sendLimit']) and not reset_passed:
        print_with_timestamp('Limit Exceeded: {0}'.format(email_context['sendLimit']))
        return(False, email_context)
    elif reset_passed:
        # Split logic for Limit Types & compare limit and count based on type of limit
        print_with_timestamp('Reset Time Branch: ')
        if email_context['limitType'] == 'total':
            if reset_passed:
                resetDT = nowDT
        elif email_context['limitType'] == 'perHour':
            if reset_passed:
                resetDT = (nowDT + timedelta(hours=1))
        elif email_context['limitType'] == 'perDay':
            if reset_passed:
                resetDT = (nowDT + timedelta(days=1))
        else:
            resetDT = (nowDT + timedelta(days=1))
            print_with_timestamp('1-day Default')
    else:
        print_with_timestamp('Limit Checks Passed')
    
    email_context['resetDT'] = resetDT

    # update lastDT, update resetAfterDT as appropriate
    if (limit_count <= email_context['limitCount'] or resetDT >= origReset):
        email_context = updateEmailContext(
            email_context['email'], 
            email_context['domain'], 
            limitType=email_context['limitType'], 
            sendLimit=email_context['sendLimit'], 
            limitCount=limit_count, 
            totalSent=total_sent, 
            resetDT=email_context['resetDT'], 
            firstDT=email_context['firstSendDT'])

        print_with_timestamp('Authorized')
        return(True, email_context)
    else:
        email_context = updateEmailContext(
            email_context['email'], 
            email_context['domain'], 
            limitType=email_context['limitType'], 
            sendLimit=email_context['sendLimit'], 
            limitCount=limit_count, 
            resetDT=email_context['resetDT'], 
            firstDT=email_context['firstSendDT'], 
            totalSent=email_context['totalSent']
            )
        print_with_timestamp('Unauthorized')
        return(False, email_context)


def send_limit_notice(fwd_sender, subject, limitCount, limit=max_email_checks, limitType='perDay'):
    print_with_timestamp('Trying to send limit notice: {0}'.format(limitCount))
    
    #TODO DB Check if sendLimitNoticeAfter is old(Need way to track when new notification emails should be sent)

    subject = 'RE: {0}'.format(subject)
    limitText = ''
    if limitType == 'perDay':
        limitText = 'You sent {0} in the last 24hrs. '.format(limitCount) #Using limit count here since I don't want to advertise limits

    message_body = ('It seems you have exceeded your phishing check limit. {0}<br>Please wait to check more emails.<br><br>'
        '<a href="http://www.phishing.org/what-is-phishing">What is Phishing?</a>'.format(limitText)
        )

    #message_body += auth_forward + '\n\n' + spam_detected '\n\n' + virus_detected

    try:
        response = ses_client.send_email(
                Source='check@urltotal.com',
                Destination={
                    'ToAddresses': [
                        fwd_sender[1],
                    ]
                },
                Message={
                    'Subject': {
                        'Data': subject,
                        'Charset': 'UTF-8'
                    },
                    'Body': {
                        'Text': {
                            'Data': message_body,
                            'Charset': 'UTF-8'
                        },
                        'Html': {
                            'Data': message_body,
                            'Charset': 'UTF-8'
                        }
                    }
                },
                ReplyToAddresses=[
                    'check@urltotal.com',
                ],
                ReturnPath='check@urltotal.com',
                SourceArn='arn:aws:ses:us-west-2:815246487488:identity/check@urltotal.com',
                ReturnPathArn='arn:aws:ses:us-west-2:815246487488:identity/check@urltotal.com',
                Tags=[
                    {
                        'Name': 'urltotal',
                        'Value': 'limited'
                    },
                ]
            )
    except Exception as eg:
        print_with_timestamp('Unable to send email. Data:\n{0}-----------------\n{1}'.format(fwd_sender, eg))


def getForwardedEmail(email_msg):
    '''
    This function is meant to parse the full email to find just the text of the "Suspicious" email that was forwarded
    '''
    print_with_timestamp('Trying to get just the original forwarded email.')
    body = ''

    if email_msg.is_multipart():
        for part in email_msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))

            # skip any text/plain (txt) attachments
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                body = part.get_payload(decode=True)  # decode
                break
    # not multipart - i.e. plain text, no attachments, keeping fingers crossed
    else:
        body = email_msg.get_payload(decode=True)
    return body


def findEmailLinks(email_msg, fwd_sender):
    '''
    Takes all email links within a document using a regular expression to find valid URLs
    removes any email tags, and removes URLs that are in the same domain as the sender and then
    returns a list of the URLs 
    '''
    #TODO See if BeautifulSoup from bs4 will help here, 'findall()' supposedly gets all URLs from links

    html_links = re.findall(r'href=[3D]*"[-A-Za-z0-9+&#/%?=~_|!:,.;\(\)]*"', email_msg) #Finds only valid links using standard charsets
    if debug >=3:
        print_with_timestamp('Links: {0}'.format(html_links))

    link_index = 0
    for link in html_links:
        html_links[link_index] = link.split('"',2)[1] #Split on '\' to remove email tags
        link_index += 1

    #Remove links to the same domain as the forwarding sender
    print_with_timestamp('fwd_sender: {0}'.format(fwd_sender))
    check_links = [x for x in (html_links) if (re.search(fwd_sender,x) == None)]

    #Remove duplicate links
    temp_urls=list()
    for url in check_links:
        try:
            p_url = urlparse(url).geturl()
            if not p_url in temp_urls and 'tel:' not in p_url:
                temp_urls.append(p_url)
        except Exception as url_ex:
            print_with_timestamp('Had trouble parsing a URL from the link in the email. \n{0}'.format(url_ex))
    check_links = list(set(temp_urls))

    if debug >= 2:
        print_with_timestamp('Check Links: ' + str(check_links))
    
    return(check_links)


def requestURLChecks(mail_id, urls, vt_resources, delay=1):
    '''
    Sends messages to SQS queue to notify the EC2 instance to go and try getting a screenshot of the website root domain.
    '''
    
    allURLs = {'urls':urls,
                'vt_resources':vt_resources}

    data = '{0}:{1}'.format(mail_id, allURLs)
    try:
        print_with_timestamp('Got queue URL {0}'.format(screenshotQueueURL))
        resp = sqs_client.send_message(QueueUrl=screenshotQueueURL, MessageBody=data, DelaySeconds=delay)
        if debug >= 2:
            print_with_timestamp('Send result: {0}'.format(resp))
    except Exception as e:
        raise Exception('Could not record link! {0}'.format(e))


def saveResults(mail_id, test_results, tempResults=False):
    '''
    Saves a "test_results" dictionary to S3 using mail_id as the key
    '''
    if tempResults:
        resBucket = 'urltotal-tempresults'
    else:
        resBucket = 'urltotal-results'

    try:
        print_with_timestamp('Trying to save results {0}'.format(test_results))
        temp_file = '/tmp/email_results-{0}'.format(mail_id)
        with open(temp_file, 'w+') as file:
                json.dump(test_results, file)
    except Exception as er:
        print_with_timestamp('Error: Unable to create JSON file for results. {0}'.format(er))
        raise

    try:
        response = s3_client.upload_file(temp_file, resBucket, '{0}.res'.format(mail_id))
    except:
        print_with_timestamp('Error: Unable to upload results to S3!')
        raise

    if response == None:
            return(False)        
    return(True)


def email_flattener(email_msg):
    ''' Remove extra line breaks denoted by an '=' in the email message so I can match patterns better later.'''
    email_flattener = re.compile(r'=$\n',re.MULTILINE)
    flat_email = re.sub(email_flattener, '', str(email_msg))
    return flat_email


#Grabs email stored in S3 and then gets screenshots of links in the email
def email_handler(event, context):
    if debug >= 2:
        print_with_timestamp(event['Records'][0]['s3'])

    upload_bucket = event['Records'][0]['s3']['bucket']['name']
    uploads_prefix = event['Records'][0]['s3']['object']['key']
    email_msg = getS3email(upload_bucket, uploads_prefix)

    # Verify the sender is authorized
    # TODO3 Future version should check database for an ID and "From" email match
    try:
        if(check_secret == 1):
            secret_index = email_msg['subject'].index(secretID) > -1
    except Exception as ef:
        raise ValueError('User ID, secret, or sender of email check was not validated!')

    fwd_sender = email_msg['From']

    sender_email = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',fwd_sender)
    clean_subject = re.subn(r'[^-A-Za-z0-9+?&@#/%=~_!:,.\(\)\s]','',email_msg['subject']) #allow whitespace, remove ';|'
    emailContextItems = getEmailContext(sender_email[0])

    print_with_timestamp(emailContextItems)

    if emailContextItems:
        authorized, updatedContextItems = isAuthorized(emailContextItems)
        try:
            try:
                totalSent = updatedContextItems['totalSent']
            except Exception as ts:
                print_with_timestamp('Unable to find total sent.\n{0}'.format(updatedContextItems))
                totalSent = updatedContextItems['limitCount']
            if authorized == None or not authorized:
                #TODO2 - Figure out a way to only send this notice once per reset period
                send_limit_notice(fwd_sender=sender_email, subject=clean_subject, limitCount=updatedContextItems['limitCount'])
                raise ValueError('Purposefully Vague Error: Email sender problem')
            # If we find "pass" in the Authentication results then we trust the forward came from who they say they are
            unauth_sender_found = email_msg['Authentication-Results'].lower().index('pass')
            trusted = True
        except Exception as ea:
            raise
        finally:
            # if delete_emails == 1:
            print_with_timestamp('Recommend deleting object from S3:\n{0}/{1}'.format(upload_bucket, uploads_prefix))
            # TODO3 - Make a queue for deleteing emails?
            # s3_client.delete_object(Bucket = upload_bucket, Key = uploads_prefix)
    else:   
        print_with_timestamp('Adding new email context {0}'.format(sender_email))
        email_parts = sender_email[1].split('@',2)
        email_name = email_parts[0]
        domain_name = email_parts[1]
        response = newEmailContext(email_name, domain_name, limitType='perDay', limitCount=1, firstDT=nowDT)
        if debug >= debug_threshold + 1:
            print_with_timestamp('New email context response: {0}',format(response))
        #raise ValueError('New email added! Check it!')

    #Parse main body of the email
    flat_email = email_flattener(email_msg)
    forwarded_email = email_flattener(getForwardedEmail(email_msg))
    try:
        forwarded_from = re.search(r'From.*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',forwarded_email)[0]
        forwarded_email_from = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',forwarded_from)[0]
        print_with_timestamp('Forwarded email is from: {0}'.format(forwarded_email_from))
    except Exception as ef:
        print_with_timestamp('Could not parse forwarded email: {0}'.format(ef))
        pass

    if debug >= debug_threshold + 1:
        print_with_timestamp(flat_email)

    # Set up fwd_sender to not check links from the sender's domain
    sender_domain = fwd_sender.split('@',2)[1][:-1]
    email_links = findEmailLinks(flat_email, sender_domain)

    if debug >= debug_threshold + 1:
        print_with_timestamp('Email Links Found! \n{0}'.format(email_links))
    mail_id = uploads_prefix.split('/',2)[1]

    #Dictionary to pass results to the sender's email address (using zero trust model)
    #Test_results are stored as follows:
    # summary : Overall Determination
    # trust_fwd : DKIM results
    # spam : SES SPAM filter Results
    # virus : SES Virus Scan filter results
    # urls : links used for screenshots of URLs checked in the email. (More or less depending on how it gets used in the future)
    # attachments : Analysis of attachments
    # orginal_text : text based version of the email flattened to do NLP later
    test_results = {
        'version':1,
        'subject':clean_subject,
        'summary':'Seems Safe', 
        'fwd_sender':fwd_sender,
        'trust_fwd':'FAIL - Fwd not from a trusted forwarding authority', 
        'spam':'FAIL - SES Spam check thinks it\'s SPAM', 
        'virus':'FAIL - SES Virus scan thinks there\'s a virus',
        'urls':{'0':'No Results'},
        'attachments':{'mime_match':False,'Executable':False,'MS Office':False,'PDF':False},
        'forwarded_email':forwarded_email,
        'forwarded_email_from':forwarded_email_from,
        'vt_results':{'0':'No Results'},
        'recommendation': list()
    }

    try:
        spam_detected = email_msg['X-SES-Spam-Verdict'].lower().index('pass')
        test_results['spam'] = 'Pass - This email didn\'t trigger SPAM alerts'
    except:
        test_results['spam'] = 'FAIL - This looks like SPAM'
        test_results['summary'] = 'Looks like SPAM'
        test_results['recommendation'].append('Unsubscribe from email lists unless you explicity want the email '
            'and trust them to protect your information. If the original sender has an account management '
            'portal, they may offer options for reducingthe number of emails the send to you. '
            'Consider opting out of newsletters, promotions, discounts, status updates etc.'
            )
        #TODO 2 - Handle this situation better, need a way to update the results after thorough analysis still
        pass

    try:
        virus_detected = email_msg['X-SES-Virus-Verdict'].lower().index('pass')
        test_results['virus'] = 'Pass - No viruses detected'
    except:
        test_results['virus'] = 'FAIL - Virus Found'
        test_results['summary'] = 'DANGEROUS'
        test_results['recommendation'].append('The email triggered virus alerts which means it has malicious looking code.'
            'Block the sender (You can undo it later if needed). Delete '
            'the email and notify your IT support. '
            )
        
    # Checked earlier for trusted sender. Since this checks for the person forwarding it being authentic
    # TODO 2 Check for DKIM values better (Some EDU addresses weren't sending DKIM so it was not processing them)
    try:
        test_results['trust_fwd'] = 'Pass: Email was forwarded from a trusted sender' 
        test_results['urls'] = None
        test_results['num_urls'] = len(email_links)
        test_results['attachments'] = getAttachmentTypes(email_msg)

    except Exception as e:
        print_with_timestamp(e)
        raise

    s_set = set([])
    vt_resources = list([])

    if email_links != None:
        # Request screenshots and URL checks of domains in the original email
        s_links = list()
        try:            
            #TODO 2 Make the requests all at the same time for only the root domain site

            for link in email_links:
                #Clean up the urls for checks
                p_url = sanitizeUrl(link, removeSubDirs=False)
                url = p_url.geturl()
                p_net = p_url.netloc
                p_domain = '.'.join(p_net.split('.',3)[1:3])
                if not p_domain in trusted_domains:
                    s_links.append(url)

            s_set = set(s_links) # Make sure we only have a unique set of links
            print_with_timestamp('Domains: {0}'.format(s_set))

            test_results['urls'] = list(s_set)
            test_results['num_urls'] = len(s_set) # Used as a metric for phishing

             # Using s_set to create a list with similar attributes needed for vt_results
            vt_index = 0

            # Check a random sample of the urls using max as the number to check
            least_links = min(max_links_to_check,len(s_set))
            check_urls = random.sample(s_set, least_links)
            print_with_timestamp('Checking {0} links!!!'.format(len(check_urls)))
            vt_resources = list(check_urls)
            for s_url in check_urls:
                #VT Check Initiation - Response includes link to get results of the test
                params = {'apikey':vt_api_key, 'url':s_url}

                print_with_timestamp('Checking against Virus Total')
                vt_result = requests.post(vt_domain_scan, data=params)
                print_with_timestamp(vt_result.text)
                
                json_results = vt_result.json()
                if json_results['response_code'] == 1:
                    vt_resources[vt_index] = vt_result.json()['resource']

                vt_index += 1

            if debug >= 2:
                print_with_timestamp('Virus Total Results:\n{0}'.format(vt_resources))
        except Exception as eh:
            print_with_timestamp(eh)
            raise 

        saveResults(mail_id, test_results, tempResults=True)
        requestURLChecks(mail_id, check_urls, vt_resources) # mail_id is used to track which links went to specific messages
        # TODO 4: Supplement VT URL checks with custom blacklists of IPs and Domains

    else:
        saveResults(mail_id, test_results)

    #TODO move the email object in S3 to a 'processed email bucket' so that if we miss something we can just process all the emails in the bucket and recover more easily
    return 'Finished'
