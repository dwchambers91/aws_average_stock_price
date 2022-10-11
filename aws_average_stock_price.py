#!/usr/bin/env python
# coding: utf-8

import subprocess
from time import sleep

import boto3
# In[1]:
import ipython_genutils

s3 = boto3.resource('s3')
ec2 = boto3.client('ec2')


# In[2]:


owner_key = boto3.client('sts').get_caller_identity()['Account']


# In[3]:


sns_client = boto3.client('sns')
sns_client.create_topic(Name='lab1-test-topic')
sns_topic = sns_client.create_topic(Name='lab1-test-topic')
topic_arn = sns_topic['TopicArn']


# In[4]:


sns_topic2 = sns_client.create_topic(Name='lab1-test-topic-A-to-B')
topic_arn2 = sns_topic['TopicArn']


# In[5]:


#instresponse = ec2.reboot_instances(InstanceIds=[instance_id], DryRun=False)
s3_client = boto3.client('s3')
bucket_name='11132021chambers-5'
r_bucket_name='chambersbucket2-4452-thurs'
s3Bucket = s3_client.create_bucket(Bucket=bucket_name)
rBucket= s3_client.create_bucket(Bucket=r_bucket_name)


# In[6]:


bucket_arn = 'arn:aws:s3:::'+bucket_name
r_bucket_arn = 'arn:aws:s3:::'+r_bucket_name
role_arn = 'arn:aws:iam::'+owner_key+':role/lambda_role'
lambda_client = boto3.client('lambda')


# In[7]:


# Print out bucket names
for bucket in s3.buckets.all():
    print(bucket.name)


# In[8]:


import json

# Create a bucket policy
bucket_name = bucket_name
bucket_policy = {
    'Version': '2012-10-17',
    'Statement': [{
        'Sid': 'AddPerm',
        'Effect': 'Allow',
        'Principal': '*',
        'Action': ['s3:PutObject'],
        'Resource': f'arn:aws:s3:::{bucket_name}/*'
    }]
    
}
# Convert the policy from JSON dict to string
bucket_policy = json.dumps(bucket_policy)

# Set the new policy
s3_client.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)


# In[9]:


r_bucket_policy = {
    'Version': '2012-10-17',
    'Statement': [{
        'Sid': 'AddPerm',
        'Effect': 'Allow',
        'Principal': '*',
        'Action': ['s3:PutObject'],
        'Resource': f'arn:aws:s3:::{r_bucket_name}/*'
    }]
    
}
# Convert the policy from JSON dict to string
r_bucket_policy = json.dumps(r_bucket_policy)

# Set the new policy
s3_client.put_bucket_policy(Bucket=r_bucket_name, Policy=r_bucket_policy)


# In[10]:


sns_subscribe = sns_client.subscribe(
    TopicArn=topic_arn,
    Protocol='email',
    Endpoint='dwchambe@uno.edu')


# In[11]:


#zip file included in submission
import os

in_file = open(r"C:\Users\dougw\my-math-function\lab1-deployment-package.zip", "rb") # opening for [r]eading as [b]inary
deploymentPackageBytes = in_file.read() # if you only wanted to read 512 bytes, do .read(512)
in_file.close()


# In[12]:


response = lambda_client.create_function(
    FunctionName='lambda_function_alpha',
    Runtime='python3.7',
    Role=role_arn,
    Handler='lambda_function_alpha.lambda_handler',
    Code={
        'ZipFile': deploymentPackageBytes
    },
)


# In[13]:


response = lambda_client.create_function(
    FunctionName='lambda_function_beta',
    Runtime='python3.7',
    Role=role_arn,
    Handler='lambda_function_beta.lambda_handler',
    Code={
        'ZipFile': deploymentPackageBytes
    },
)


# In[14]:

sleep(1)
response = lambda_client.put_function_concurrency(
    FunctionName='lambda_function_beta',
    ReservedConcurrentExecutions=1
)


# In[47]:

sleep(1)
response = lambda_client.put_function_concurrency(
    FunctionName='lambda_function_alpha',
    ReservedConcurrentExecutions=1
)


# In[51]:

sleep(1)
response = lambda_client.update_function_configuration(
    FunctionName='lambda_function_alpha',
    Timeout=600

)


# In[15]:


lambda_client = boto3.client('lambda')
addLambdaPerms = lambda_client.add_permission(
    FunctionName='lambda_function_alpha',
    StatementId='Addperms3',
    Action='lambda:InvokeFunction',
    Principal="s3.amazonaws.com",
    SourceArn=bucket_arn,
    SourceAccount=owner_key
)


# In[16]:


addLambdaPerms = lambda_client.add_permission(
    FunctionName='lambda_function_alpha',
    StatementId='AddpermsAsync',
    Action='lambda:InvokeAsync',
    Principal="s3.amazonaws.com",
    SourceArn=bucket_arn,
    SourceAccount=owner_key
)


# In[17]:


addLambdaPerms = lambda_client.add_permission(
    FunctionName='lambda_function_beta',
    StatementId='Addperms3',
    Action='lambda:InvokeFunction',
    Principal="s3.amazonaws.com",
    SourceArn=bucket_arn,
    SourceAccount=owner_key
)


# In[18]:


function_list =lambda_client.list_functions()
function_list
funct_alpha_arn = function_list['Functions'][0]['FunctionArn']
funct_beta_arn = function_list['Functions'][1]['FunctionArn']


# In[19]:


subscribe = sns_client.subscribe(
    TopicArn=topic_arn,
    Protocol='lambda',
    Endpoint=funct_alpha_arn,
)


# In[20]:


lambda_client = boto3.client('lambda')
addLambdaPermsSNSPut = lambda_client.add_permission(
    FunctionName='lambda_function_alpha',
    StatementId='AddpermsSNSPut',
    Action='lambda:InvokeFunction',
    Principal=owner_key,
    SourceArn=topic_arn,
    SourceAccount=owner_key
)


# In[21]:


lambda_client.add_permission(
     FunctionName='lambda_function_beta',
     StatementId='AddpermsAtoB',
     Action='lambda:InvokeFunction',
     Principal=owner_key,
     SourceArn=funct_alpha_arn,
     SourceAccount=owner_key
 )


# In[22]:


lambda_client.add_permission(
     FunctionName='lambda_function_beta',
     StatementId='AddpermsS3',
     Action='lambda:PutObject',
     Principal=owner_key,
     SourceArn=funct_alpha_arn,
     SourceAccount=owner_key
 )


# In[23]:


lambda_client.add_permission(
     FunctionName='lambda_function_alpha',
     StatementId='AddpermsAtoB',
     Action='lambda:InvokeFunction',
     Principal=owner_key,
     SourceArn=funct_beta_arn,
     SourceAccount=owner_key
 )


# In[24]:


iam_client = boto3.client('iam')
iam_policy={
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:AWSServiceName": "robomaker.amazonaws.com"
                }
            }
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "cloudwatch:*",
                "cloudformation:*",
                "ec2:AssociateRouteTable",
                "ec2:AttachInternetGateway",
                "ec2:CreateInternetGateway",
                "ec2:CreateNetworkInterfacePermission",
                "ec2:CreateRoute",
                "ec2:CreateRouteTable",
                "ec2:CreateSecurityGroup",
                "ec2:CreateSubnet",
                "ec2:CreateTags",
                "ec2:CreateVpc",
                "ec2:DeleteNetworkInterface",
                "ec2:DeleteSubnet",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs",
                "kinesis:*",
                "kinesisvideo:*",
                "lex:*",
                "logs:*",
                "polly:*",
                "robomaker:*",
                "rekognition:*",
                "s3:*",
                "sns:*",
                "iam:passrole",
                "lambda:*"
            ],
            "Resource": "*"
        }
    ]
}


# In[26]:


get_ipython().run_cell_magic('cmd', '', 'aws lambda add-permission --function-name "lambda_function_alpha" --statement-id "s3-put-event" --action "lambda:InvokeFunction" --principal "s3.amazonaws.com" --source-arn "arn:aws:s3:::11132021chambers-5" --region us-east-1')


# In[29]:


get_ipython().run_cell_magic('cmd', '', 'aws s3api put-bucket-notification-configuration --bucket 11132021chambers-5 --notification-configuration file://trigger.json')


# In[28]:


get_ipython().run_cell_magic('cmd', '', 'aws sns subscribe --protocol lambda --topic-arn arn:aws:sns:us-east-1:308076226310:lab1-test-topic-A-to-B --notification-endpoint arn:aws:lambda:us-east-1:308076226310:function:lambda_function_beta --region us-east-1')


# In[30]:


response = lambda_client.add_permission(
    Action='lambda:InvokeFunction',
    FunctionName='lambda_function_beta',
    Principal='sns.amazonaws.com',
    SourceArn='arn:aws:sns:us-east-1:308076226310:lab1-test-topic-A-to-B',
    StatementId='sns',
)

print(response)


# In[32]:



response = iam_client.put_role_policy(
    RoleName='lambda_role',
    PolicyName='testPolicy4',
    PolicyDocument=json.dumps(iam_policy)
)
response


# In[33]:


sns_policy= {
      "Version": "2008-10-17",
      "Id": "s3-publish-to-sns",
      "Statement": [{
              "Effect": "Allow",
              "Principal": { "AWS" : "*" },
              "Action": [ "SNS:Publish" ],
              "Resource": topic_arn,
              "Condition": {
                  "ArnLike": {
                      "aws:SourceArn": bucket_arn
                  }
              }   }
      ]
  }
response = sns_client.set_topic_attributes(
    TopicArn=topic_arn,
    AttributeName='Policy',
    AttributeValue=json.dumps(sns_policy)
)


# In[34]:




response = lambda_client.add_permission(
    StatementId='S3InvokLambda',
    FunctionName='lambda_function_alpha',
    Action='lambda:InvokeLambda',
    Principal='s3.amazonaws.com',
    SourceArn=bucket_arn,
)

print(response)


# In[35]:


response = sns_client.subscribe(
    TopicArn=topic_arn2,
    Protocol='lambda',
    Endpoint=funct_beta_arn
)


# In[36]:


import logging
import os

from botocore.exceptions import ClientError


def upload_file(file_name, bucket, object_name=None):

    if object_name is None:
        object_name = os.path.basename(file_name)

    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True


# In[37]:





# In[49]:


for file in os.listdir():
    if '.txt' in file:
        upload_file_bucket = bucket_name
        upload_file_key = str(file)
        s3_client.upload_file(file, upload_file_bucket, upload_file_key)


# In[ ]:


response = s3_client.get_bucket_notification_configuration(
    Bucket=bucket_name,
    ExpectedBucketOwner=owner_key
)
response

