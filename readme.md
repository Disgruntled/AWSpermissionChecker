# AWS Permissions checker config rule

Better name pending.

This is an AWS config rule code (alongside some unit tests) that you can deploy into your environment to help monitor your IAM roles for over entitlement.

This will was written using the AWS RDK (https://github.com/awslabs/aws-config-rdk) for testing, and can be deployed using the config RDK as well.

## Features of this version

-Check AWS roles for bad entitlements everytime a role changes

-report NON_COMPLIANT or COMPLIANT back to config

-detailed logs in cloudwatch

## Major Todos:

-Create companion that looks at when policy changes

-Add filter for roles should have entitlements (admins)

-break out some pieces of code into config

-support reading in-line policies (gross!)

-make it easier 

## Requirements

only requires boto3 and the aws rdk

```
pip3 install boto3
```

To install the AWS RDK, please follow the most up to date documentation on their website


## Deployment

Out of the box deployment is only setup now via AWS RDK (cloudformation), but obviously nothing is stopping you from doing this manually in the console

cd to the directory to the directory containing the permissionChecker FOLDER and:

```
rdk deploy permissionChecker
```

rdk deployment assumes that you have sufficient permissions and a properly setup environment. if any doubts, please refer to the RDK manual.

## testing

```
rdk test-local permissionChecker
```

this will execute permissionChecker_test.py 

This accepts a --verbose flag to display stdout/stderr. That functionality was actually added to RDK by me, how neat.

The test scenarios I've provided currently assume that you have iam:getpolicy and iam:getpolicyversion, and a properly setup aws environment.

the tests attempt to get aws resources that are in my AWS account. For the tests to work for anyone who isnt me in their current iteration, you must update the 'policyArn' fields in the same events in permissionChecker_test.py



