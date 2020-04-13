# AWS Permissions checker config rule

Better name pending.

This is an AWS config rule code (alongside some unit tests) that you can deploy into your environment to help monitor your IAM roles/users for over entitlement.

This will was written using the AWS RDK <https://github.com/awslabs/aws-config-rdk> for testing, and can be deployed using the config RDK as well.

## How it works / Modification

The heavy lifting is done in the checkDataAccess method.

statement ID's are extracted from IAM policies, and sent to checkDataAccess. checkDataAccess determines if it's an allow or a deny, then begins looking for toxic combinations of the resource: and action: field

This function can easily be extended by a layperson with IAM experience by modifying any one of the statements present within.

## Features of this version

-Check AWS roles and users for bad entitlements everytime the role or user changes

-Report NON_COMPLIANT or COMPLIANT back to config

-Detailed logs in cloudwatch

-Regex-based filtering in code of users/roles you want excluded

-Unit tests (no aws credentials or environment required for local testing anymore!)

## Major Todos

-Create companion that looks at when policy changes

-Break out some pieces of code into config (exclusion rule, badPatterns, logging messages)

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
