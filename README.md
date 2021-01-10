# GuardEngine
GuardEngine is an automated solution to set security baselines across multiple accounts within an AWS Organization. Lightweight governance tool that will set password policy, deploy CloudFormation templates, and enforce GuardDuty and SecurityHub. Multiple triggers set to ensure policies stay enforced even if they are removed by child account admins.

# GuardEngine Requirements:
Audit account needs to have GuardDuty and SecurityHub already setup. The detector ID will be provided in the Lambda variables sections.
Master account must have a FullAdmin role that the master account can assume. In LandingZone/ControlTower environments this is different then what is in the child accounts.

S3 bucket created in the Master account with the bucket policy below to allow all accounts in the organization to read the contents. This will be used as a central location to share CloudFormation templates. Also make sure the names of the yaml files are what you want them to show up as in CloudFormation. We use the bucket and filename to build the stack name to minimize any code changes for new templates that are added in the future. 

A shared role that allows the master account access to all the child accounts to enable GuardDuty, SecurityHub, set password policies, and deploy CloudFormation templates. If ControlTower is deployed this would be the "AWSControlTowerExecution" role that is automatically created. 

# Setup
* Create an S3 bucket for standard cloudformation templates
* Create an S3 folder called "exclusions" in the bucket above for templates that won't be deployed to every account.
* Create an SNS topic in the Audit account with the name "DeleteOpenSecurityGroup-SnsTopic" and the Access policy below, replacing the values for the ACCOUNTNUMBER and ORGID.
* Create a Lambda IAM role with the policy below in order to read Accounts IDs from AWS Organizations.
* Create a Lambda function with the GuardEngine python file and the variables below
    * DEFAULT_REGION
    * SECURITY_ACCOUNT
    * MASTER_ACCOUNT
    * INFOSEC_DETECTORID
    * TEST_TRIGGER
    * SHARED_ROLE
    * S3_TEMPLATE_BUCKET
    * Enable default EBS encryption
    * Excluded accounts (Ex: "12345","54321")
* Create triggers to execute Lambda function automatically
    * Cloudwatch event with cron job every Sunday
    * Cloudwatch event for new or update CloudFormation templates in S3 Bucket
    * Cloudwatch event for new accounts added
    * Manual Trigger from Lambda console

# Lambda policy
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:CreateLogGroup"
                ],
                "Resource": "arn:aws:logs:*:*:*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "sts:AssumeRole",
                    "organizations:DescribeCreateAccountStatus",
                    "organizations:DescribeAccount",
                    "organizations:ListAccounts",
                    "s3:*"
                ],
                "Resource": "*"
            }
        ]
    }

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

# SNS Access policy
    {
      "Version": "2008-10-17",
      "Statement": [
        {
          "Sid": "__default_statement_ID",
          "Effect": "Allow",
          "Principal": {
            "AWS": "*"
          },
          "Action": [
            "SNS:GetTopicAttributes",
            "SNS:SetTopicAttributes",
            "SNS:AddPermission",
            "SNS:RemovePermission",
            "SNS:DeleteTopic",
            "SNS:Subscribe",
            "SNS:ListSubscriptionsByTopic",
            "SNS:Publish",
            "SNS:Receive"
          ],
          "Resource": "arn:aws:sns:us-east-1:ACCOUNTNUMBER:DeleteOpenSecurityGroup-SnsTopic",
          "Condition": {
            "StringEquals": {
              "AWS:SourceOwner": "ACCOUNTNUMBER"
            }
          }
        },
        {
          "Sid": "AWSSNSPolicy",
          "Effect": "Allow",
          "Principal": {
            "AWS": "*"
          },
          "Action": "sns:Publish",
          "Resource": "arn:aws:sns:us-east-1:ACCOUNTNUMBER:DeleteOpenSecurityGroup-SnsTopic",
          "Condition": {
            "StringEquals": {
               "aws:PrincipalOrgID": "o-ORGID"
            }
          }
        }
      ]
    }

# Items to add:
* If encounter an exception send sns notification
* Automate setup with CloudFormation
* Create folder in repo for example governance templates
* Test removing the second assume function for the infosec account. probably only need one
* If a CloudFormation template is deleted then the stack should be removed from accounts. Currently it does nothing. Would need to tag stack that was created with GuardEngine so there is a condition to key off of as well so we don't delete manual stacks.

# Troubleshooting
## If existing child accounts have any of the following they will need to be deleted or removed. 

* AWS Config is already enabled - 
  * Create new admin user and get access key then run command below
        aws configure (enter access key)
        aws configservice describe-configuration-recorders
        aws configservice delete-configuration-recorder --configuration-recorder-name RECORDER-NAME-FROM-ABOVE-COMMAND
  * Delete AWSconfig service role
  * Delete AWS Config Delivery channel with the commands below
        aws configservice describe-delivery-channels
        aws configservice delete-delivery-channel --delivery-channel-name CHANNEL-NAME-FROM-ABOVE-COMMAND