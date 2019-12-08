## ACCOUNT RELATED

SSM_PARAMETER_KEY = '/IAM_Key_Rotator_Automation/session_data'

## IAM RELATED
IGNORE_TAGS = ['ignore','freeze','lock','skip']
EMAIL_TAGS_LIST = ['owner','email','email id','mail', 'email_id']

WARN_THRESHOLD = 358
REMIND_DAY_LIST = [3,5,6]
SELF_HEAL_THRESHOLD = 7
LAST_USED_THRESHOLD = 358
AGE_THRESHOLD = 365


## SES
SES_REGION = 'us-east-1'
CCADDRESS = ['genpactcloudalerts@genpact.com']
SOURCE_ADDRESS='Access Manager <genpactcloudalerts@genpact.com>'
REPORT_ADDRESS = 'genpactcloudalerts@genpact.com'
