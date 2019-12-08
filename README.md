# IAM_Key_Rotation
This Automation Rotates Keys In Accordance to Genpact Policies.

Settings Available in ```CONSTANTS.py```

Boto3 Library is Included to avoid compatibility issues.


# Policies
- Access Keys Not Used in the last 83 Days will be Deleted.
- Access Keys which were created before 83 Days and is being used, will be rotated with a newly created Key , over a Span of 7 days from the first notification.
- Deleted Keys cannot be recovered.
- Only one access Key per user is allowed to be active in any point in time except when it is being rotated with the newly created key

# Flowchart
![alt text](https://github.com/genpact-cloud/IAM_Key_Rotation/blob/master/IAM_Key_Rotation_Algo_final.png)

# Usage

1. Download ZIP Folder
2. Upload ZIP file to  Lambda (Runtime: Python 3.7)
3. Grant SES Full Access, SSM Full Access and IAM Full Access to Lambda
4. Trigger Lambda everyday using CloudWatch Events
5. Adjust Lambda Timeout
