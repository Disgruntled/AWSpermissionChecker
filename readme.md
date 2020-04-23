# AWS Permissions checker config rule

Better name pending.

This is an AWS config rule code (alongside some unit tests) that you can deploy into your environment to help monitor your IAM roles/users for over entitlement.

This will was written using the AWS RDK <https://github.com/awslabs/aws-config-rdk> for testing, and can be deployed using the config RDK as well.

## How it works / Modification

The heavy lifting is done in the checkAccess method.

statement ID's are extracted from IAM policies, and sent to checkAccess. checkAccess runs our defined checks against a given IAM statement id (SID), then begins looking for toxic that we define.
I've included some patterns that are absoloutely toxic and should be avoided on non-admins, but it is very easy for anyone to code up their own check for things that meet their organizations threat model.

This function can easily be extended by a layperson with IAM experience by modifying any one of the statements present within.

Take this example code block from checkAccess

```python
#First we're checking to see if there is an Allow entitlement,
#and if that entitlement applies to all resources (resource == '*')
if sid.Resource == '*' and sid.Effect == 'Allow':
    #Setting a custom Message to be written to cloudwatch if a there is a finding
    message = "Data Store Access Risky Entitlement"
    #Setting a new bad patterns for every check. badPatterns should always be a list even if you want one.
    badPatterns = ['s3:getobject','s3:get*','sqs:receivemessage','dynamodb:GetItem',
    'dynamodb:batchGetItem','dynamodb:getrecords', 'iam:passrole']
    #Sending the 'Action' element of the IAM policy, alongside the list of bad patterns and our message to be checked
    if checkList(sid.Action, badPatterns, message) == 'NON_COMPLIANT':
    #If there is a bad finding, this compliance must be set to NON_COMPLIANT for config to mark it as such
        compliance = "NON_COMPLIANT"
```

## Exclusion Pattern

This rule accepts 1 config rule parameter, ExceptionPattern, that will contain a pattern which if found in an IAM USER/ROLE will exclude them from compliance monitoring.

This is useful for excluding admins, as we expect someone to have this entitlement.

## Features of this version

-Check AWS roles and users for bad entitlements everytime the role or user changes

-Report NON_COMPLIANT or COMPLIANT back to config

-Detailed logs in cloudwatch

-Regex-based filtering in code of users/roles you want excluded (ExceptionPattern rule parameter)

-Unit tests (no aws credentials or environment required for local testing anymore!)

-Supports looking at bad patterns in actions/principals/resources

## Major Todos

-Create companion that looks at when policy changes

-Support reading in-line policies (gross!)

-Cloudformation and terraform deployments

## Requirements

only requires boto3 and the aws rdk

```shell
pip3 install botocore
pip3 install boto3
```

or with the provided requirements.txt file:

```shell
pip3 install -r requirements.txt
```

To install the AWS RDK, please follow the most up to date documentation on their website

## Deployment

Out of the box deployment is only setup now via AWS RDK (cloudformation), but obviously nothing is stopping you from doing this manually in the console

cd to the directory to the directory containing the permissionChecker FOLDER and:

```shell
rdk deploy permissionChecker
```

rdk deployment assumes that you have sufficient permissions and a properly setup environment. If any doubts, please refer to the RDK manual.

### Permissions for the lambda function

By chance, the default rdk entitlement created for lambda functions is almost perfectly least privileged. It will use the below, except with STS:AssumeRole on resource *, which is actually something we'd consider a risky entitlement.
This IAM policy is sufficient for the rule to run, and with no further intervention you'll get the below policy with sts:assumerole * attached as an inline-policy to your lambda role.

Some release down the road will use support creating this as a managed policy and handle it for you. Do note that if manually configuring, and using a lambda zip file, you need to update the bucket ARN in Sid 1.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::<BucketNameHostingLambdaZip>",
            "Effect": "Allow",
            "Sid": "1"
        },
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "2"
        },
        {
            "Action": [
                "config:PutEvaluations"
            ],
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "3"
        },
        {
            "Action": [
                "iam:List*",
                "iam:Describe*",
                "iam:Get*"
            ],
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "4"
        }
    ]
}
```

## testing

```shell
rdk test-local permissionChecker
```

this will execute permissionChecker_test.py

This accepts a --verbose flag to display stdout/stderr. That functionality was actually added to RDK by me, how neat.
