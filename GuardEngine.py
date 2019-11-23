# This ensures that the print function will work in python 2 and 3 versions
from __future__ import print_function

# Import needed modules for the script to run
import sys

# Default Lambda environment has an older version of boto3 that doesn't support SecurityHub
# This will install the latest version of boto3 at runtime
from pip._internal import main
main(['install', '-I', '-q', 'boto3', '--target', '/tmp/', '--no-cache-dir', '--disable-pip-version-check'])
sys.path.insert(0,'/tmp/')


# Import latest version of boto3
import boto3
from botocore.exceptions import ClientError

import botocore
import os
import json

# Lambda Environment Variables
SecurityStackName = os.environ['SECURITY_STACK_NAME']
SecurityStackURL = os.environ['SECURITY_STACK_URL']
AutoTagStackName = os.environ['AUTOTAG_STACK_NAME']
AutoTagStackURL = os.environ['AUTOTAG_STACK_URL']
TrendStackName = os.environ['TREND_STACK_NAME']
TrendStackURL = os.environ['TREND_STACK_URL']
DeleteSGStackName = os.environ['DELETE_SG_STACK_NAME']
DeleteSGStackURL = os.environ['DELETE_SG_STACK_URL']
#TestStackName = os.environ['TEST_STACK_NAME']
#TestStackURL = os.environ['TEST_STACK_URL']
default_region = os.environ['DEFAULT_REGION']
sec_account = os.environ['SECURITY_ACCOUNT']
detectorID = os.environ['INFOSEC_DETECTORID']

# List accounts in the Organization
def GetAccountIds():
    client = boto3.client('organizations')
    
    # Creating an empty array to store accounts in org
    AccountID = []
    response = client.list_accounts()

    for account in response['Accounts']:
        # Find status and only add if active since deleted accounts could show as suspended
        if account['Status'] == 'ACTIVE':
            # Append the id field from the dict 
            AccountID.append(account['Id'])
            try:
                # Running a try block to make sure the Token field is empty. Some api calls do not return everything in one pass
                while response['NextToken'] is not None:
                    response = client.list_accounts(NextToken = response['NextToken'])
                    for account in response['Accounts']:
                        if account['Status'] == 'ACTIVE':
                            AccountID.append(account['Id'])
            except KeyError:
                continue
    return AccountID

# Get email associated with child account
def GetAccountEmail(account_id):
    client = boto3.client('organizations')

    response = client.describe_account(
        AccountId=account_id)
    account_email = response['Account']['Email']
    return account_email

# Assume role from the master into the child account and pass credentials to a parameter
def assume_role(role_arn):
    sts_client = boto3.client('sts')
    try:
        assumedRoleObject = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='GuardEngine'
        )
    except botocore.exceptions.ClientError as error:
        print(error)
    return assumedRoleObject['Credentials']

# Assume role into InfoSec account and pass credentials to a parameter
def assume_role_sec(role_arn):
    sts_client = boto3.client('sts')
    try:
        assumedRoleObject = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='GuardEngine',
            ExternalId='guardenginelambda'
        )
    except botocore.exceptions.ClientError as error:
        print(error)
    return assumedRoleObject['Credentials']

# Set IAM password policy
def deploy_password_policy(credentials):
    print("Setting password policy")
    client = boto3.client('iam',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'])
    response = client.update_account_password_policy(
        MinimumPasswordLength=15,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        MaxPasswordAge=90,
        PasswordReusePrevention=24)
    return response

# Log into InfoSec account and send GuardDuty invite if not already a member
def GuardDutyInvite(credentials, account, account_email):
    # Invite GuardDuty members from InfoSec account
    client = boto3.client('guardduty',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'])

    # use a variable called response to store the results of the boto get members api call
    # AccountID comes from the for each command and the detectorID is an environment variable
    # We use .get to pull the members sections from the output
    response = client.get_members(
        AccountIds=[account], 
        DetectorId=detectorID).get('Members')

    # Check to see if the length of the response is zero which means there is no results for the member field
    if len(response) == 0:
        try:
            # Create GuardDuty member
            createMember = client.create_members(
                DetectorId=detectorID,
                AccountDetails=[
                    {
                        'AccountId': account,
                        'Email': account_email
                    },
                ]
            )
            print("New GuardDuty Member created")
            # Create invite for new member
            inviteMember = client.invite_members(
                DetectorId=detectorID,
                AccountIds=[account],
                DisableEmailNotification=True)
            print("Sending GuardDuty invite")
        except:
            print("Something went wrong")
    else:
        # if the length is anything over zero then we can assume this account is already a member
        print("Account is already a Guard Duty member")

# Log into client account, enable GuardDuty, and accept invitation if not already a member
def GuardDutyConfig(credentials):
    client = boto3.client('guardduty',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'])

    response = client.list_detectors().get('DetectorIds')

    # Check to see if the length of the response is zero which means there is no results for the member field 
    if len(response) == 0:
        try:
            # Create DetectorID
            createDetectorId = client.create_detector(
                Enable=True,
                FindingPublishingFrequency='FIFTEEN_MINUTES')
            print("New GuardDuty detector ID created")
            # Get new detectorId
            response = client.list_detectors().get('DetectorIds')
            # Remove brackets from detectorId
            clientDetectorId = ''.join(response)
        except:
            print("Something went wrong")
    else:
        # if the length is anything over zero then we can assume this account has a detectorID
        # Remove brackets from detectorId
        clientDetectorId = ''.join(response)
        print("Account already has a detector")

    # List and accept invitations
    # Should check to see if account is already a member instead of assuming by the exception that it is
    try:
        invitation = client.list_invitations().get('Invitations')
        invitationID = invitation[0]['InvitationId']
        acceptInvitation = client.accept_invitation(
            DetectorId=clientDetectorId,
            MasterId=sec_account,
            InvitationId=invitationID)
        print("Accept GuardDuty invitation")
    except:
        print('Guard Duty invitation is already accepted')

def SecurityHubInvite(credentials, account, account_email):
    # Invite SecurityHub members from InfoSec account
    client = boto3.client('securityhub',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'])

    # use a variable called response to store the results of the boto get members api call
    # AccountID comes from the for each command
    # We use .get to pull the members sections from the output
    response = client.get_members(
        AccountIds=[account]).get('Members')

    # Check to see if the length of the response is zero which means there is no results for the member field
    if len(response) == 0:
        try:
            # Create SecurityHub member
            createMember = client.create_members(
                AccountDetails=[
                    {
                        'AccountId': account,
                        'Email': account_email
                    },
                ]
            )
            print("New SecurityHub Member created")
            # Create invite for new member
            inviteMember = client.invite_members(
                AccountIds=[account])
            print("SecurityHub invite sent")
        except:
            print("Something went wrong")
    else:
        # if the length is anything over zero then we can assume this account is already a member
        print("Account is already a member of SecurityHub")

# Log into client account, enable Security hub, and accept invitation if not already a member
def SecurityHubConfig(credentials):
    client = boto3.client('securityhub',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'])

    try:
        # Enable SecurityHub
        enableSecurityHub = client.enable_security_hub()
        print("Enable SecurityHub")
    except:
        print("SecurityHub is already enabled")

    # List and accept invitations
    # Should check to see if account is already a member instead of assuming by the exception that it is
    try:
        invitation = client.list_invitations().get('Invitations')
        invitationID = invitation[0]['InvitationId']
        acceptInvitation = client.accept_invitation(
            MasterId=sec_account,
            InvitationId=invitationID)
        print("Accept SecurityHub invitation")
    except:
        print('Security Hub invitation is already accepted') 

# Function to deploy or update the Security stack
def deploy_stacks(credentials, default_region, stackname, stackurl):
    client = boto3.client('cloudformation',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'])
    # Need to check if the stack is already there and set a variable
    CheckStackName = None
    try:
        CheckStackName = client.describe_stacks(StackName=stackname)
    except botocore.exceptions.ClientError as error:
        #If the stack does not exist it will throw an error. We want to except the error and set a variable
        CheckStackName = None

    if CheckStackName is None:
        # Create new stack
        try:
            response = client.create_stack(
                StackName=stackname,
                TemplateURL=stackurl,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
                OnFailure='ROLLBACK')
            print('Creating',stackname,'stack')
        except botocore.exceptions.ClientError as error:
            print(error)
    else:
        try:
            # Update Existing stack
            response = client.update_stack(
                StackName=stackname,
                TemplateURL=stackurl,
                UsePreviousTemplate=False,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'])
            print(stackname,'stack is updating')
        except botocore.exceptions.ClientError as error:
            print('No changes to existing',stackname,'stack')

def lambda_handler(event, context):
    print("boto3 version:"+boto3.__version__)
    print("botocore version:"+botocore.__version__)

    # Triggers = New Account creation, S3 update, and CloudWatch weekly schedule
    print(event)

    # list accounts in Org into an array
    AccountId = []
    # lines below for testing this will switch to listing out org members
    #AccountId = [event['account_id']]
    # Comment above line then uncomment below when ready for full pass
    AccountId = GetAccountIds()

    # Loop through array
    for account in AccountId:
        # find account email
        print('--------------------')
        print(account)
        account_email = GetAccountEmail(account)
        print(account_email)

        # Assume role into Infosec
        sec_role_arn = 'arn:aws:iam::' + sec_account + ':role/FullAdmin'
        security_credentials = assume_role_sec(sec_role_arn)
    
        # Check for account in GuardDuty and add member if it doesn't exist
        #if account != sec_account:
        #    GuardDutyInvite(security_credentials,account,account_email)
    
        # Check for account in Security Hub and add member if it doesn't exist
        #if account != sec_account:
        #    SecurityHubInvite(security_credentials,account,account_email)

        # Assume role into child account
        org_role_arn = 'arn:aws:iam::' + account + ':role/FullAdmin'
        child_credentials = assume_role(org_role_arn)
        # Logic to not continue if exception was found to assume role

        # Deploy password policy
        deploy_password_policy(child_credentials)
        
        # Deploy the security baseline cloudformation stack
        #deploy_stacks(child_credentials,default_region,SecurityStackName,SecurityStackURL)

        # Deploy the AutoTag cloudformation stack
        #deploy_stacks(child_credentials,default_region,AutoTagStackName,AutoTagStackURL)

        # Deploy the Trend cloudformation stack
        #deploy_stacks(child_credentials,default_region,TrendStackName,TrendStackURL)

        # Deploy the Delete Security Group cloudformation stack
        # Placeholder to have exclusion for future production accounts that do need 0.0.0.0 open
        # Change as needed or add another or statement to include additional accounts for exclusion
        if account != '123456789' or account != '987654321':
            deploy_stacks(child_credentials,default_region,DeleteSGStackName,DeleteSGStackURL)        

        # Deploy the test cloudformation stack
        deploy_stacks(child_credentials,default_region,TestStackName,TestStackURL)

        #Accept the GuardDuty invite from InfoSec account
        #if account != sec_account:
        #    GuardDutyConfig(child_credentials)

        # Accept the securityHub invite from InfoSec account
        #if account != sec_account:
        #    SecurityHubConfig(child_credentials)





# ---------------------------------------------------------------------------------------------------------------------
# items to add
# If encounter an exception send sns email
# Ensure S3 bucket is encrypted
# Detect drift in CF template and send sns notification




# Clean up existing resources to deploy through stack
#--------------------------------
# Delete operation role
# Delete Operation policy 
# Delete Cloudwatch log group
# Delete AWS Config recorder
    #Create new admin user and get access key
    #aws configure (enter access key)
    #aws configservice describe-configuration-recorders
    # get the name then run
    #aws configservice delete-configuration-recorder --configuration-recorder-name default
    # replace default with the name of the recorder
# Delete AWSconfig service role
# Delete AWS Config Delivery channel
    #aws configservice describe-delivery-channels
    #aws configservice delete-delivery-channel --delivery-channel-name default
    # replace default with the channel name
# Delete CloudTrail Trail
