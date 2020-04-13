# Author: liam.wadman@gmail.com
# Purpose: deliver tests for AWS config rule
# Version .1, MVP
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#    
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import botocore
import boto3

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::Role'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()

###########################
#Definining the output of iam.get_policy and iam.get_policy_version. The RDK boilerplate is using magicmock elsehwere, so for consistency we are sticking with it.
#Intrepid developers who want to test policies should can modify the get_policy and get_policy_version responses suitably.
#You most likely just want to add/remove/edit statements id (SIDS) in the get_policy_version return value.
###########################
IAM_CLIENT_MOCK = MagicMock()

IAM_CLIENT_MOCK.get_policy.return_value = {
   "Policy":{
      "PolicyName":"broken_bucket_admin",
      "PolicyId":"ANPAICTZAYSZXH6ZTO2XO",
      "Arn":"arn:aws:iam::123456789012:policy/broken_bucket_admin",
      "Path":"/",
      "DefaultVersionId":"v4",
      "AttachmentCount":1,
      "PermissionsBoundaryUsageCount":0,
      "IsAttachable":True,
      "Description":"just a test",
},
   "ResponseMetadata":{
      "RequestId":"0ef08c84-48d8-4e05-8422-56e582e3e837",
      "HTTPStatusCode":200,
      "HTTPHeaders":{
         "x-amzn-requestid":"0ef08c84-48d8-4e05-8422-56e582e3e837",
         "content-type":"text/xml",
         "content-length":"806",
         "date":"Mon, 13 Apr 2020 00:51:40 GMT"
      
},
      "RetryAttempts":0
   
}
}


IAM_CLIENT_MOCK.get_policy_version.return_value = {
   "PolicyVersion":{
      "Document":{
         "Version":"2012-10-17",
         "Statement":[
            {
               "Sid":"VisualEditor0",
               "Effect":"Allow",
               "Action":[
                  "s3:PutAccountPublicAccessBlock",
                  "s3:GetAccountPublicAccessBlock",
                  "s3:ListAllMyBuckets",
                  "s3:HeadBucket"
               
],
               "Resource":"*",
               "Condition":{
                  "IpAddress":{
                     "aws:SourceIp":"127.0.0.2/32"
                  
}
               
}
            
},
            {
               "Sid":"VisualEditor1",
               "Effect":"Allow",
               "Action":"s3:*",
               "Resource":"arn:aws:s3:::*",
               "Condition":{
                  "IpAddress":{
                     "aws:SourceIp":"127.0.0.1/32"
                  
}
               
}
            
},
            {
               "Sid":"VisualEditor2",
               "Effect":"Allow",
               "Action":"s3:*",
               "Resource":"arn:aws:s3:::*/*",
               "Condition":{
                  "IpAddress":{
                     "aws:SourceIp":"127.0.0.1/32"
                  
}
               
}
            
},
            {
               "Sid":"VisualEditor4",
               "Effect":"Allow",
               "Action":"*:*",
               "Resource":"*"
            
}

         
]
      
},
      "VersionId":"v4",
      "IsDefaultVersion":True,
   
},
   "ResponseMetadata":{
      "RequestId":"58b76237-982c-415b-ad61-8eda8f922b81",
      "HTTPStatusCode":200,
      "HTTPHeaders":{
         "x-amzn-requestid":"58b76237-982c-415b-ad61-8eda8f922b81",
         "content-type":"text/xml",
         "content-length":"3098",
         "vary":"accept-encoding",
         "date":"Mon, 13 Apr 2020 00:52:05 GMT"
      
},
      "RetryAttempts":0
   
}
}

#########################
#End IAM data declaration
#########################

#Note: if you want to put more boto clients into your config rule, you must override them here in order for your test to be succesful.
class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'iam':
            return IAM_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('permissionChecker')

class ComplianceTest(unittest.TestCase):


#To make the tests work in your own account, you may change the policy ARNS in this event in the "AttachedManagedPolicies" statement.
#Names are not necesarrily relevant, ARNS are.

#TODO: Put events into a config file.
    sampleEvent1 = '''
    {
    "messageType":"ConfigurationItemChangeNotification",
    "notificationCreationTime":"2017-12-23T22:11:18.158Z",
    "configurationItem": {
        "version": "1.2",
        "accountId": "123456789012",
        "configurationItemCaptureTime": "2016-11-06T03:41:52.719Z",
        "configurationItemStatus": "OK",
        "configurationStateId": "1478403712719",
        "configurationItemMD5Hash": "91a47a3c0184f9b29cfb3e354ff887dd",
        "arn": "arn:aws:iam::123456789012:role/service-role/config-role-ezcrc2",
        "resourceType": "AWS::IAM::Role",
        "resourceId": "AROAIY7FPU7KRV7IZBNPC",
        "resourceName": "config-role-ezcrc2",
        "awsRegion": "global",
        "availabilityZone": "Not Applicable",
        "resourceCreationTime": "2016-03-10T23:52:10.000Z",
        "tags": {},
        "relatedEvents": [],
        "relationships": [
            {
                "resourceType": "AWS::IAM::Policy",
                "resourceId": "ANPAIJWML3NX3NT6UAGO4",
                "resourceName": "ELB-policy",
                "relationshipName": "Is attached to CustomerManagedPolicy"
            },
            {
                "resourceType": "AWS::IAM::Policy",
                "resourceId": "ANPAILY3GNWH4C77WJ6QM",
                "resourceName": "config-role-ezcrc2-AWSConfigDeliveryPermissions-us-west-2",
                "relationshipName": "Is attached to CustomerManagedPolicy"
            }
        ],
        "configuration": {
            "path": "/service-role/",
            "roleName": "config-role-ezcrc2",
            "roleId": "AROAIY7FPU7KRV7IZBNPC",
            "arn": "arn:aws:iam::123456789012:role/service-role/config-role-ezcrc2",
            "createDate": "2016-03-10T23:52:10.000Z",
            "assumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "config.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "instanceProfileList": [],
            "rolePolicyList": [],
            "attachedManagedPolicies": [
                {
                    "policyName": "cloudformation_ec2_all",
                    "policyArn": "arn:aws:iam::123456789012:policy/cloudformation_ec2_all"
                }
            ]
        },
        "supplementaryConfiguration": {}
        }
    }
'''




    def setUp(self):
        pass

    def test_sample(self):
        self.assertTrue(True)


    def test_sample_2(self):
        '''
        Test IAM role with multiple managed policies, at least 1 of which triggers a NON_COMPLIANT
        Testing assumes and requires available AWS entitlements to read IAM
        '''
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.sampleEvent1), {})
        resp_expected = []
        #If customizing your own event, the resource id (AROAnnn) must match. Update here and in the event.
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AROAIY7FPU7KRV7IZBNPC', 'AWS::IAM::Role'))
        assert_successful_evaluation(self, response, resp_expected)


####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    #exit(event_to_return)
    #print(event_to_return)
    return event_to_return

def build_lambda_scheduled_event(rule_parameters=None):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_expected_response(compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    if not annotation:
        return {
            'ComplianceType': compliance_type,
            'ComplianceResourceId': compliance_resource_id,
            'ComplianceResourceType': compliance_resource_type
            }
    return {
        'ComplianceType': compliance_type,
        'ComplianceResourceId': compliance_resource_id,
        'ComplianceResourceType': compliance_resource_type,
        'Annotation': annotation
        }

def assert_successful_evaluation(test_class, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        test_class.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        test_class.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        test_class.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        test_class.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            test_class.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        test_class.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            test_class.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            test_class.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            test_class.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            test_class.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                test_class.assertEquals(response_expected['Annotation'], response[i]['Annotation'])

def assert_customer_error_response(test_class, response, customer_error_code=None, customer_error_message=None):
    if customer_error_code:
        test_class.assertEqual(customer_error_code, response['customerErrorCode'])
    if customer_error_message:
        test_class.assertEqual(customer_error_message, response['customerErrorMessage'])
    test_class.assertTrue(response['customerErrorCode'])
    test_class.assertTrue(response['customerErrorMessage'])
    if "internalErrorMessage" in response:
        test_class.assertTrue(response['internalErrorMessage'])
    if "internalErrorDetails" in response:
        test_class.assertTrue(response['internalErrorDetails'])

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    STS_CLIENT_MOCK.reset_mock(return_value=True)
    STS_CLIENT_MOCK.assume_role = MagicMock(return_value=assume_role_response)

##################
# Common Testing #
##################

class TestStsErrors(unittest.TestCase):

    def test_sts_unknown_error(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
