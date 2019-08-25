##
## Version 0.190104
##

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
urlt_feedback = 'https://feedback.urltotal.com/'

summary_status = {"safe":"Seems Safe",
    "spam":"Looks like SPAM",
    "phishy":"Smells Phishy",
    "virus":"Dangerous"}

# S3 Resources
screenshot_bucket = 'urltotal-screenshots'
results_bucket = 'urltotal-results'
feedback_bucket = 'feedback.urltotal.com'
s3_client = boto3.client('s3', region_name=region)

# SES Resources
ses_client = boto3.client('ses')

debug_threshold = 1

#Checks if debug is enabled, then print the message if it is.
def print_with_timestamp(*args):
    if (debug >= debug_threshold):
        print(datetime.utcnow().isoformat(), *args)


def sanitizeUrl(url):
    '''
    Returns a parsed bare URL with non-standard ASCII characters and parameters removed
    Removes all parameters and variables in the URL (Avoiding flagging individual users by visiting sites with their assigned parameters)
    '''
    s_url = re.subn(r'[^-A-Za-z0-9+?&@#/%=~_:,.\(\)]','',url) #Remove crazy non-standard URL characters
    #s_url = re.subn(r'([\|;\&\$\>\<\'\\!>>#]|%3B)','',s_url) #Remove likely cmd injection characters
    s_url = s_url[0].split('?',2)[0]
    #TODO2 do something with the second half of s_url which would enable better 
    #tracking of crazy links which are more likely to be spam
    p_url = urlparse(s_url)
    if debug >= debug_threshold:
        print_with_timestamp('Sanitized URL: {0}'.format(p_url.geturl()))
    return(p_url)

def getURLDomain(parsed_url):
    '''
    '''
    if parsed_url.netloc:
        p_net = parsed_url.netloc
    else:
        p_net = parsed_url.path.split('/')[0]
    
    return(p_net)

def url_to_filename(parsed_url):
    '''Takes a sanitized URL and returns filename version of the main parent domain
    '''
    p_net = getURLDomain(parsed_url)
    
    try:
        re.match(r'([a-z])([a-z0-9]+\.)*[a-z0-9]+\.[a-z.]+', p_net)
        return(p_net + '.png')
    except Exception as urle:
        print_with_timestamp('Unable to convert URL to a filename! {0}: {1}'.format(parsed_url, urle))
        return(None)

def insert_text(thestring, position, insert='<br>'):
    '''Inserts text into the middle of a string
    '''
    longi = len(thestring)
    if position < 0 or position > longi:
        raise ValueError("The position given to insert text is not valid!")

    newstring   =  thestring[:position] + insert + thestring[position:] 
    return newstring   


def insert_every(thestring, interval=110, insert='<br>'):
    '''Inserts text at every lineLimit. Great for adding new lines!'''
    lineLimit = interval
    while lineLimit < len(thestring) and lineLimit > 0:
        while thestring[lineLimit:lineLimit+1] != ' ' and lineLimit > 0:
            lineLimit = lineLimit-1
        thestring = insert_text(thestring, lineLimit, insert)
        lineLimit = lineLimit + interval + len(insert)
    return(thestring)

def getResults(results_file, bucket=results_bucket):
    #Dictionary to pass results to the sender's email address (using zero trust model)
    #results are stored as follows:
    # summary : Overall Determination
    # trust_fwd : DKIM results
    # spam : SES SPAM filter Results
    # virus : SES Virus Scan filter results
    # urls : links used for screenshots of URLs checked in the email. (More or less depending on how it gets used in the future)
    # attachments : Analysis of attachments
    # orginal_text : text based version of the email flattened to do NLP later
    respS3 = None
    try:
        print_with_timestamp('Getting saved results for feedback. {0}'.format(results_file))
        temp_file = '/tmp/email_results-{0}'.format(results_file)
        respS3 = s3_client.download_file(results_bucket, results_file, temp_file)
    except ClientError as ce:
        print_with_timestamp('Unable to get saved results: {0}\n{1}'.format(respS3, ce))
        raise
    with open(temp_file, 'r') as file:
        results = json.load(file)
    # Cleanup temp files
    os.remove(temp_file)
    print_with_timestamp('Got Results!: {0}'.format(results['summary']))
    return(results)

def getPhishyMeter(summary):
    start = '<img src="https://feedback.urltotal.com/'
    end = '" height="96" width="360"><br>'
    if summary_status['safe'] in summary:
        file = 'PhishyMeter_Safe.png'
    elif summary_status['spam'] in summary:
        file = 'PhishyMeter_SPAM.png'
    elif summary_status['phishy'] in summary:
        file = 'PhishyMeter_Phishy.png'
    elif summary_status['virus'] in summary:
        file = 'PhishyMeter_Virus.png'
    else:
        start = ''
        file = ''
        end = ''
    return(start+file+end)
    

def create_feedback_page(mailid):
    '''Saves an HMTL page hosted in s3 where users provide feedback for the email analysis they received.'''
    filename = mailid + '.html'
    try:
        print_with_timestamp('Saving feedback page for ID: {0}'.format(mailid))
        temp_file = '/tmp/{0}'.format(filename)
        with open(temp_file, 'w+') as file:
                file.write('<html>'
                    '<head><title>URLTotal Feedback</title></head>'
                    '<body>'
                    '<div id=logo><img src="https://feedback.urltotal.com/Name.png" height="115" width="265"></div>'
                    '<h3>URLTotal-Feedback Site</h3>'
                    '<p>Our goal is to provide you with a highly dependable phishing email analysis.<br>'
                    'Help make it better!</p>'
                    '<p>Email Reference: <b>{mailid}</b> <br>Please copy the email reference above into the form below.</p>'
                    '<iframe src="https://docs.google.com/forms/d/e/1FAIpQLSf49dATXPZhhJ9XQIpv740TnxMAHnBot99Wj8phHr25oG7RLQ/viewform?embedded=true" width="640" height="1359" frameborder="0" marginheight="0" marginwidth="0">Loading...</iframe>'
                    'If you need us to delete an email you sent on accident, please ensure you put the word "PURGE" in the comments and paste the Email reference again as well.'
                    '</body>'
                    '</html>'.format(mailid=mailid)
                    )
    except Exception as er:
        print_with_timestamp('Error: Unable to create HTML file for feedback. {0}'.format(er))
        raise

    respS3 = ''
    try:
        respS3 = s3_client.upload_file(
            temp_file, 
            feedback_bucket, 
            filename, 
            ExtraArgs={
                'ACL':'public-read',
                'ContentType':'text/html'
                }
            )
    except:
        print_with_timestamp('Error: Unable to upload html to S3 website!', respS3)
        raise
    return(respS3)
    

def send_result(event, context):
    if debug >= debug_threshold + 1:
        print_with_timestamp(event['Records'][0]['s3'])

    results_bucket = event['Records'][0]['s3']['bucket']['name']
    uploads_prefix = event['Records'][0]['s3']['object']['key']
    mailid = uploads_prefix.split('.')[0]

    # Use the event info to retrive the urltotal-results
    results = getResults(results_file=uploads_prefix, bucket=results_bucket)
    print_with_timestamp('Trying to send results: {0}'.format(results))

    # parse the urls part of the results to generate image references for each screenshot
    urls = results['urls']
    temp_urls=list()
    for url in urls:
        url =  getURLDomain(urlparse(url)) #Using only the domain part of the URL since trying not to trigger tracking of users
        if not url in temp_urls:
            temp_urls.append(url)
    urls = list(set(temp_urls))
    print_with_timestamp('Unique URLs: {0}\n{1}'.format(len(urls),urls))

    #Build HTML for each individual screenshot
    screenshot_rows = ''
    if urls != None:
        s3L = 'https://s3-us-west-2.amazonaws.com/'
        valid_screenshots = 0
        for url in urls:
            #Check if url has screenshot or not
            try:
                p_url = sanitizeUrl(url)
                filename = url_to_filename(p_url)

                print_with_timestamp('Filename: {0}'.format(filename))

                object_head = s3_client.head_object(Bucket=screenshot_bucket, Key=filename)
                if debug >= debug_threshold + 1:
                    print_with_timestamp('S3 check response: {0}'.format(object_head))
                
                if object_head:
                    screenshot_url_row = '<tr><td><h3>{0}</h3></td></tr>'.format(url)
                    screenshot_row = '<tr><td><img src="{0}{1}/{2}.png" alt="{2}" height="480" width="640"></td></tr>'.format(s3L, screenshot_bucket, url)
                    screenshot_rows = screenshot_rows + screenshot_url_row + screenshot_row
                    valid_screenshots += 1
                else:
                    print_with_timestamp('URL preview not found. {0}'.format(filename))
            except ClientError as ce:
                print_with_timestamp(ce)
                print_with_timestamp('URL preview not found this time. {0}'.format(filename))
            except:
                raise

        #Used in email text to help make words "plural"
        plural = 's'
        if valid_screenshots <= 1:
            plural = ''

        #Generate final HTML for screenshots if any were found
        if valid_screenshots > 0:        
            screenshot_html = (
                '<div id=screenshots>'
                '<h3>Link Preview{plural}:</h3>'
                '<table>'
                '{screenshot_rows}'
                '</table></div>'
                ).format(plural=plural, screenshot_rows=screenshot_rows)
        else:
            screenshot_html = ''

    orig_subject = results['subject']
    short_subject = orig_subject[:min(len(orig_subject),25)][0]
    summary = results['summary']

    final_subject = '"RE: {0}"'.format(short_subject)
    print_with_timestamp('Subject: {0}'.format(final_subject))

    #Feedback site creation & link creation
    try:
        create_feedback_page(mailid)
    except Exception as e:
        print_with_timestamp('There was a problem saving the feedback HTML page. {0}', e)
        raise

    #TODO Change format the recommendations, line breaks
    recommendation_text = '\n'.join(results['recommendation'])
    # recommendation_text = insert_every(recommendation_text, 110, '<br>') #Inserts a break every 110 chars

    # Create beautiful HTML version of the email
    message_body_html = (
        '<html xmlns="http://www.w3.org/1999/xhtml" >'
        '<head>' 
        '<body>'
        '<div id=top><h2>URL Total Email Phishing Check</h2></div>'
        '<div id=summary><h3>{subject}<br></h3></div>'
        '<div id=results>'
        '<h3>Results: {summary}</h3><br>'
        '{phishy_meter}'
        '<a href="https://feedback.urltotal.com/{mailid}.html">(Wrong Result?)</a><br>'
        'SPAM Check: <b>{spam}</b><br>'
        'Virus Check: <b>{virus}</b><br>'
        'Number of URLs Checked: <b>{links}</b><br>'
        'Language Score: <b>{language}</b><br>'
        '<div id=recommendation style="width:420px;height:auto;word-wrap:break-word;"><h4>Recommendation:</h4> {recommendation}<br></div><br>'
        '</div>').format(
                subject=final_subject,
                recommendation=recommendation_text,
                mailid=mailid,
                spam=results['spam'],
                virus=results['virus'],
                links=valid_screenshots,
                language=results['language_score'],
                summary=summary,
                phishy_meter=getPhishyMeter(summary)
            )
    if urls != None:
        style_tag = (
                '<style type="text/css">'
                '.codebox {'
                'border:1px solid black;'
                'background-color:#EEEEFF;'
                'width:300px;'
                'overflow:auto;'    
                'padding:10px;'
                '}'
                '.codebox code {'
                '/* Styles in here affect the text of the codebox */'
                'font-size:0.9em;'
                '}'
                '</style>'
            )
        message_body_html = (
                '{style_tag}'
                '{email_body}'
                '{screenshots}'
                '<h4>Feedback:</h4>Please give URLTotal <a href="https://feedback.urltotal.com/{mailid}.html">constructive criticism!</a><br><br>'
                '<div id=disclaimer style="width:420px;height:auto;word-wrap:break-word;"><h4>Disclaimer:</h4><br>'
                'URLTotal\'s goal is to give you the best opportunity to determine if '
                'the email you received is malicious or not, but this service is not '
                'perfect and makes mistakes. Please use your best judgement and exercise '
                'caution whenever opening emails.<br><br>'
                'This service is provided without any guarantee or promise of accuracy. '
                'Even emails that seem safe, may still be malicious. </div><br>'
                '<div id=logo><img src="https://feedback.urltotal.com/Name.png" height="115" width="265"></div>'
                '</body>'
                '</html>'.format(style_tag=style_tag, email_body=message_body_html, screenshots=screenshot_html,mailid=mailid)
            ) 

    # Create ugly text version of the email
    message_body = ('Summary: ' + summary + '\n' + 
        'Virus Test: ' + str(results['virus']) + '\n' +
        'SPAM Test: ' + str(results['spam']) + '\n' +
        'Language Score: ' + str(results['language_score']) + '\n' +
        'Recommendation: ' + recommendation_text + '\n')

    # Pass return-path as part of the results.
    email_destination = results['fwd_sender']

    if debug >= 2:
        print_with_timestamp(event['Records'][0]['s3'])
    
    #TODO 3 - Get AI Assessment results from Wherever I decide to save it. (S3 for now)

    try:
        response = ses_client.send_email(
                Source='check@urltotal.com',
                Destination={
                    'ToAddresses': [
                        email_destination,
                    ]
                },
                Message={
                    'Subject': {
                        'Data': final_subject,
                        'Charset': 'UTF-8'
                    },
                    'Body': {
                        'Text': {
                            'Data': message_body,
                            'Charset': 'UTF-8'
                        },
                        'Html': {
                            'Data': message_body_html,
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
                        'Value': 'check1'
                    },
                ]
            )
    except Exception as eg:
        print_with_timestamp('Unable to send email. Data:\n{0}-----------------\n{1}'.format(results, eg))
        raise(eg)

    print_with_timestamp('Email Sent: {0}'.format(response))
    return('Email Sent!')