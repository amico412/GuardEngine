# GuardEngine
GuardEngine is an automated solution to set security baselines across multiple accounts within an AWS Organization. Lightweight governance tool that will set password policy, deploy CloudFormation templates, and enforce GuardDuty and SecurityHub. Multiple triggers set to ensure policies stay enforced even if they are removed by child account admins.

# GuardEngine Requirements:
Audit account needs to have GuardDuty and SecurityHub already setup. The detector ID will be provided in the Lambda variables sections.
Master account must have a FullAdmin role that the master account can assume. In LandingZone/ControlTower environments this is different then what is in the child accounts.

S3 bucket created in the Master account with the bucket policy below to allow all accounts in the organization to read the contents. This will be used as a central location to share CloudFormation templates. Also make sure the names of the yaml files are what you want them to show up as in CloudFormation. We use the bucket and filename to build the stack name to minimize any code changes for new templates that are added in the future. 

A shared role that allows the master account access to all the child accounts to enable GuardDuty, SecurityHub, set password policies, and deploy CloudFormation templates. If ControlTower is deployed this would be the "AWSControlTowerExecution" role that is automatically created. In the LandingZone deployment scripts this is "". 

# Setup
Create an S3 bucket for standard cloudformation templates
Create an S3 folder in the bucket above for exception templates
Create a Lambda IAM role with the policy below in order to read Accounts IDs from AWS Organizations.
Create a Lambda function with the GuardEngine python file

# S3 Bucket policy
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SharedArtifacts",
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::BUCKETNAME",
                "arn:aws:s3:::BUCKETNAME/*"
            ],
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalOrgID": "ORGID"
                }
            }
        }
    ]
}


# Items to add:
If encounter an exception send sns notification
Ensure S3 bucket is encrypted
Detect drift in CF template and send sns notification
Switch individual CF stacks to an array loop and just execute everything in the S3 bucket. Create an exceptions folder for one off stacks that shouldn't be on every account
Turn Lambda function creation into a CloudFormation template so everything is automated
Deploy shared Service Catalog portfolios to child accounts
Test removing the second assume function for the infosec account. probably only need one
If a CloudFormation template is deleted then the stack should be removed from accounts. Currently it does nothing.

# Troubleshooting
If existing child accounts have any of the following they will need to be deleted or removed. 

AWS Config is already enabled - 
  Create new admin user and get access key then run command below
    aws configure (enter access key)
    aws configservice describe-configuration-recorders
    aws configservice delete-configuration-recorder --configuration-recorder-name RECORDER-NAME-FROM-ABOVE-COMMAND
  Delete AWSconfig service role
  Delete AWS Config Delivery channel with the commands below
    aws configservice describe-delivery-channels
    aws configservice delete-delivery-channel --delivery-channel-name CHANNEL-NAME-FROM-ABOVE-COMMAND
