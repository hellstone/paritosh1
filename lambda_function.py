import json
import boto3
import logging
import CONSTANTS
import re
import sys
from base64 import b64decode
from string import Template
from datetime import datetime, timezone

# Global Variables
session_data = dict()


# Boto3 Resources
logger = logging.getLogger()
logger.setLevel(logging.INFO)
ssm = boto3.client('ssm')
iam = boto3.client('iam')
ses = boto3.client('ses',region_name=CONSTANTS.SES_REGION)

action_path = 'action.html'
action_template = open(action_path,'r')
action_text = action_template.read()
action_template.close()

deletion_path = 'deletion.html'
deletion_template = open(deletion_path,'r')
deletion_text = deletion_template.read()
deletion_template.close()

notify_path = 'notify.html'
notify_template = open(notify_path,'r')
notify_text = notify_template.read()
notify_template.close()

report_path = 'report.html'
report_template = open(report_path,'r')
report_text = report_template.read()
report_template.close()

def load_session_data():
    global session_data
    try:
        logger.info('[INIT] Loading Session Data from Parameter Store ...')
        session_data = json.loads(ssm.get_parameter(Name=CONSTANTS.SSM_PARAMETER_KEY)['Parameter']['Value'])
        logger.info(json.dumps(session_data))
    except Exception as e:
        logger.warn('[INIT] Unable to Load Data from Parameter Store. Creating New Session')
    return

def get_account_alias():
    logger.info('[INIT] Getting Account Information ...')
    if iam.list_account_aliases()['AccountAliases']:
        return iam.list_account_aliases()['AccountAliases'][0]
    else:
        return str(boto3.client('sts').get_caller_identity().get('Account'))

def load_users():
    logger.info('[INIT] Loading Users from AWS IAM ...')
    response = iam.list_users()
    while(True):
        for user in response['Users']:
            yield user['UserName']

        if not response.get('IsTruncated'):
            break
        marker = response.get('Marker')
        response = iam.list_users(Marker=marker)

def is_frozen(user,tags):
    for tag in [tag for tag in (tags or [])]:
        if tag['Key'].lower().strip() in CONSTANTS.IGNORE_TAGS:
            logger.info('[VALIDATION] Checking if User Account is Frozen : True')
            return True
    logger.info('[VALIDATION] Checking if User Account is Frozen : False')
    return False

def get_user_email(user,tags):
    logger.info('[LOAD] Fetching User Email ID')
    return user if is_valid_email(user) else get_user_email_from_tag(user,tags)

def get_user_email_from_tag(user,tags):
    email = None
    for tag in [tag for tag in (tags or [])]:
        if tag['Key'].lower().strip() in CONSTANTS.EMAIL_TAGS_LIST:
            logger.info('[VALIDATION] Checking For Email ID in Tags for ' + user)
            if is_valid_email(tag['Value']):
                email = tag['Value']
                break
    return email

def is_valid_email(email):
    logger.info('[VALIDATION] Validating Email ID')
    matcher = re.match(r'([^@|\s]+@[^@]+\.[^@|\s]+)', email)
    return matcher != None

def report(user, account_alias):
    logger.info('[REPORT] Reporting user to Support Team')
    subject = 'Invalid IAM User Mail ID'
    substitution  =   dict(
                user= user,
                account = account_alias)
    global report_text
    content      = Template(report_text).safe_substitute(substitution)
    ses.send_email(
                    Destination   =     { 'CcAddresses': CONSTANTS.CCADDRESS,
                                          'ToAddresses': [CONSTANTS.REPORT_ADDRESS] },
                    Message       =     { 'Subject': {'Charset': 'UTF-8','Data': subject},
                                          'Body': {'Html': {'Charset': 'UTF-8','Data': content}}},
                    Source        =     CONSTANTS.SOURCE_ADDRESS)

def already_notified(user):
    return user in session_data

def days_since_notified(user):
    today = datetime.utcnow().replace(tzinfo=timezone.utc)
    delta = today - datetime.fromtimestamp(session_data[user]['notified_on']).replace(tzinfo=timezone.utc)
    logger.info('[CALC] Days Since Last Notified : ' + str(delta.days))
    return delta.days

def days_since_last_used(key_id):
    response = iam.get_access_key_last_used(AccessKeyId=key_id)
    if 'LastUsedDate' not in response['AccessKeyLastUsed']:
        return sys.maxsize
    today = datetime.utcnow().replace(tzinfo=timezone.utc)
    delta = today - response['AccessKeyLastUsed']['LastUsedDate']
    logger.info('[CALC] Days Since Last Used : ' + str(delta.days))
    return delta.days

def send_action_mail(user,account_alias,key_id,secret_id,email_id,action,body):
    logger.info('[ALERT] Sending ' + action + ' Mail')
    subject = 'IAM Access Key ' + action
    substitution  =   dict(
                user= user,
                account = account_alias,
                key_id = key_id,
                secret_id = secret_id,
                actioned = action,
                body = body)
    global action_text
    content      = Template(action_text).safe_substitute(substitution)
    ses.send_email(
                    Destination   =     { 'CcAddresses': CONSTANTS.CCADDRESS,
                                          'ToAddresses': [email_id] },
                    Message       =     { 'Subject': {'Charset': 'UTF-8','Data': subject},
                                          'Body': {'Html': {'Charset': 'UTF-8','Data': content}}},
                    Source        =     CONSTANTS.SOURCE_ADDRESS)

def notify_user(user,account_alias,key,email_id,countdown) :
    logger.info('[ALERT] Sending Reminder Notification Mail')
    subject = 'AWS IAM Access Key Expired'
    substitution  =   dict(
                user= user,
                account = account_alias,
                key_id = key['AccessKeyId'],
                countdown = countdown)
    global notify_text
    content      = Template(notify_text).safe_substitute(substitution)
    ses.send_email(
                    Destination   =     { 'CcAddresses': CONSTANTS.CCADDRESS,
                                          'ToAddresses': [email_id] },
                    Message       =     { 'Subject': {'Charset': 'UTF-8','Data': subject},
                                          'Body': {'Html': {'Charset': 'UTF-8','Data': content}}},
                    Source        =     CONSTANTS.SOURCE_ADDRESS)
    return

def deletion_warning_email(user,account_alias,key,email_id,countdown) :
    logger.info('[ALERT] Sending Deletion Warning Mail')
    subject = 'Access Keys Scheduled for Deletion'
    substitution  =   dict(
                user= user,
                account = account_alias,
                key_id = key['AccessKeyId'],
                countdown = countdown)
    global deletion_text
    content      = Template(deletion_text).safe_substitute(substitution)
    ses.send_email(
                    Destination   =     { 'CcAddresses': CONSTANTS.CCADDRESS,
                                          'ToAddresses': [email_id] },
                    Message       =     { 'Subject': {'Charset': 'UTF-8','Data': subject},
                                          'Body': {'Html': {'Charset': 'UTF-8','Data': content}}},
                    Source        =     CONSTANTS.SOURCE_ADDRESS)
    return

def create_key(user,account_alias,email_id):
    logger.info('[ACTION] Creating New Key')
    response = iam.create_access_key(UserName=user)
    body = 'Please update your dependencies with the below credentials before 7 days. Post 7 days your current old key will be disabled.'
    send_action_mail(user,account_alias,str(response['AccessKey']['AccessKeyId']),str(response['AccessKey']['SecretAccessKey']),email_id,'Created ', body)
    return

def delete_keys(user,account_alias,keys,email_id):
    for key in keys:
        key_id = key['AccessKeyId']
        logger.info('[ACTION] Deleting Key :'+ key_id)
        response = iam.delete_access_key(UserName=user, AccessKeyId=key_id)
        send_action_mail(user,account_alias,key_id,'Masked',email_id,'Deleted ','Deleted keys cannot be recovered.')
    return

def disable_key(user,account_alias,key,email_id):
    logger.info('[ACTION] Disabling Key : ' + key['AccessKeyId'])
    response = iam.update_access_key(AccessKeyId=key['AccessKeyId'],Status='Inactive',UserName=user)
    send_action_mail(user,account_alias,key['AccessKeyId'],'Masked',email_id,'Disabled ','')
    return

def get_age(key):
    logger.info('[CALC] Getting Age of Key : ' + key['AccessKeyId'])
    today = datetime.utcnow().replace(tzinfo=timezone.utc)
    delta = today - key['CreateDate']
    return delta.days

def remove_user_from_notify_record(user):
    logger.info('[UPDATESESSION] Removing User from Session History')
    global session_data
    if user in session_data: del session_data[user]
    return

def add_user_to_notify_record(user):
    logger.info('[UPDATESESSION] Adding User to Session History')
    global session_data
    session_data[user]= {'notified_on': datetime.utcnow().timestamp()}
    return

def choose_actionable_key(key1,key2):
    key1_age = get_age(key1)
    key2_age = get_age(key2)
    key1_last_used_in_days = days_since_last_used(key1['AccessKeyId'])
    key2_last_used_in_days = days_since_last_used(key2['AccessKeyId'])
    if key1_age > CONSTANTS.AGE_THRESHOLD and key2_age > CONSTANTS.AGE_THRESHOLD:
        return key1 if key1_last_used_in_days > key2_last_used_in_days else key2
    else:
        return key1 if key1_age > key2_age else key2

def run_cred_manager():
    account_alias = get_account_alias()
    for user in load_users():
        logger.info('Validating User : ' + user)
        tags = iam.list_user_tags(UserName=user)['Tags']
        keys = iam.list_access_keys(UserName=user)['AccessKeyMetadata']
        ## Check if user is Frozen
        if is_frozen(user, tags):
            continue

        ## Ignore Users with No Access Keys
        if not keys:
            logger.info('[SKIP] Skipping User with No Access Keys: ' + user)
            continue

        ## Report Users with Invalid Email ID
        email_id = get_user_email(user,tags)
        if not email_id:
            logger.info('[SKIP] Skipping User with Invalid Email: ' + user)
            report(user, account_alias)
            continue

        ## Collect Active and Inactive Keys
        logger.info('Analyzing User Credentials: ' + user)
        active_keys = list()
        disabled_keys = list()
        for key in keys :
            if key['Status'] == 'Active':
                active_keys.append(key)
            else:
                disabled_keys.append(key)

        ## Ignore Users with No Active Keys
        if not active_keys:
            logger.info('[SKIP] Skipping User with No Active Keys: ' + user)
            continue


        if len(active_keys) == 1:
            logger.info('[INFO] Found 1 Active Key')
            active_key = active_keys[0]
            key_age_days = get_age(active_key)
            if key_age_days < CONSTANTS.WARN_THRESHOLD:
                logger.info('User Compliant: ' + user)
                continue
            else:
                if already_notified(user):
                    logger.info('[INFO] Previously Warned User')
                    if days_since_notified(user) in CONSTANTS.REMIND_DAY_LIST:
                        notify_user(user,account_alias,active_key,email_id, CONSTANTS.SELF_HEAL_THRESHOLD - days_since_notified(user) )
                        continue
                    elif days_since_notified(user) >= CONSTANTS.SELF_HEAL_THRESHOLD:
                        disable_key(user,account_alias, active_key,email_id)
                        remove_user_from_notify_record(user)
                        continue
                    else:
                        logger.info('[INFO] No Reminder Today for ' + user)
                        continue
                else:
                    logger.info('[INFO] Found New User with Outdated Access Key: ' + user)
                    if days_since_last_used(active_key['AccessKeyId']) <= CONSTANTS.LAST_USED_THRESHOLD:
                        if disabled_keys:
                            logger.info('[INFO] Deleting Disabled Key of ' + user)
                            delete_keys(user,account_alias,disabled_keys,email_id)
                        create_key(user,account_alias,email_id)
                        add_user_to_notify_record(user)
                        continue
                    else:
                        deletion_warning_email(user,account_alias,active_key,email_id,CONSTANTS.SELF_HEAL_THRESHOLD)
                        add_user_to_notify_record(user)
                        continue

        elif len(active_keys) == 2:
            logger.info('[INFO] Found 2 Active Keys')
            active_key1 = active_keys[0]
            active_key2 = active_keys[1]
            actionable_key = choose_actionable_key(active_key1,active_key2)
            if already_notified(user):
                logger.info('[INFO] Previously Warned User')
                if days_since_notified(user) in CONSTANTS.REMIND_DAY_LIST:
                    notify_user(user,account_alias,
                                actionable_key,email_id,
                                CONSTANTS.SELF_HEAL_THRESHOLD - days_since_notified(user) )
                    continue
                elif days_since_notified(user) >= CONSTANTS.SELF_HEAL_THRESHOLD:
                    disable_key(user,account_alias,
                                actionable_key,email_id)
                    remove_user_from_notify_record(user)
                    continue
                else:
                    logger.info('[INFO] No Reminder Today for ' + user)
                    continue
            else:
                logger.info('[INFO] New Non Compliant User')
                deletion_warning_email(user,account_alias,actionable_key,email_id,CONSTANTS.SELF_HEAL_THRESHOLD)
                add_user_to_notify_record(user)
                continue

def store_session_data():

    logger.info('[INFO] Dumping Session Data to Parameter Store...')
    logger.info(session_data)
    try:
        ssm.put_parameter(      Name=CONSTANTS.SSM_PARAMETER_KEY,
                                Description='IAM Key Rotation Automation Session Data',
                                Value=json.dumps(session_data),
                                Type='String',
                                Overwrite=True)
    except Exception as e:
        logger.warn('Unable to Write Data to Parameter Store:' +  str(e))

def lambda_handler(event, context):
    try:
        load_session_data()
        run_cred_manager()
        store_session_data()
    except Exception as e:
        logger.warn('Error during key rotation : ' + str(e))
    # TODO implement
    return {
        'statusCode': 200,
        'body': json.dumps('Execution Successful')
    }
