# AWS Moose

![Lacework](https://user-images.githubusercontent.com/6440106/152378397-90c862e9-19fb-4427-96d0-02ca6c87f4dd.png)

## Overview
Lacework can integrate with AWS Moose, a security data lake that is based on the [OCSF standard](https://schema.ocsf.io/).
Lacework integrates as a data source and provides our real-time security findings. These security findings include software and infrastructure-as-code (IaC) vulnerabilities, cloud resource security misconfigurations, and known and unknown security threat behaviors.

## Architecture
![moose](https://user-images.githubusercontent.com/6440106/200464957-6fd1df7d-e3ed-4e86-994b-60dd0bc0dbc0.png)

## CloudFormation Deployment
CloudFormation is used to set up the Lacework integration with AWS Moose. The CloudFormation template creates the EventBridge rules, IAM permissions, SNS topic, SQS queue, Lambda event transformation function and the Lacework outbound security alert channel.

### Prerequisites
* Administrator access to a Lacework instance
* [Lacework Admin API Key and Secret](https://docs.lacework.com/api/api-access-keys-and-tokens)

### Deploy the CloudFormation Template

1. Click on the following Launch Stack button to go to your CloudFormation console and launch the template.

   [![Launch](https://user-images.githubusercontent.com/6440106/153987820-e1f32423-1e69-416d-8bca-2ee3a1e85df1.png)](https://console.aws.amazon.com/cloudformation/home?#/stacks/create/review?templateURL=https://lacework-alliances.s3.us-west-2.amazonaws.com/lacework-moose/templates/moose-integration.yml)

   For most deployments, you only need the Basic Configuration parameters.
   ![basic](https://user-images.githubusercontent.com/6440106/200466378-c7940e9a-128a-40c3-8281-03cadea31561.png)
   
2. Specify the following Basic Configuration parameters:
    * Enter a **Stack name** for the stack.
    * Enter the **Moose S3 Bucket Name**.
    * Enter **Your Lacework URL**.
    * If you Lacework instance has the Organization feature enabled, enter the **Lacework Sub-Account Name**. Otherwise, leave this field blank.
    * Enter your **Lacework Access Key ID** and **Lacework Secret Key** that you copied from your API Keys file. See [here](https://docs.lacework.com/console/generate-api-access-keys-and-tokens).
     
3. Click **Next** through to your stack **Review**.
4. Accept the AWS CloudFormation terms and click **Create stack**.

### Troubleshooting
Troubleshooting this integration can be done by monitoring the CloudWatch logs for two Lambda functions. One Lambda function is responsible for some of the initial setup during the CloudFormation deployment. The second Lambda function transforms Lacework security alerts to the OCSF security findings for AWS Moose.

#### Initial Setup Troubleshooting
Some initial set up during the CloudFormation deployment is handled by a Lambda function _stack-name_-LaceworkMooseSetupFunction-_xxxx_. Specifically, it configures the Alert Channel and Alert Rules that are required to send Lacework Security Alerts to the second Lambda function for transformation into OCSF and AWS Moose.
To investigate any issues, use the following steps:

1. Go to Lambda in your AWS management console.
2. Find the Lambda function with the name _stack-name_-LaceworkMooseSetupFunction-_xxxx_.
3. Click the **Monitor** tab.
4. Click the button **View logs in CloudWatch** to launch CloudWatch into a new tab.
5. View the **Log stream** debug for errors.

![CloudWatch](https://user-images.githubusercontent.com/6440106/200621487-1588221c-ceb0-4e44-b587-9ede48dfdd28.png)

#### Security Findings Event Troubleshooting
If there are issues with Lacework Security Alerts being transformed to OCSF and AWS Moose, investigate the Lambda function _stack-name_-LaceworkEventSetupFunction-_xxxx_. It transforms Lacework Security alerts into OCSF Security Findings format and delivers these in Parquet file format to the AWS Moose S3 bucket.
To investigate any issues, use the following steps:

1. Go to Lambda in your AWS management console.
2. Find the Lambda function with the name _stack-name_-LaceworkMooseEventFunction-_xxxx_.
3. Click the **Monitor** tab.
4. Click the button **View logs in CloudWatch** to launch CloudWatch into a new tab.
5. View the **Log stream** debug for errors.

![CloudWatch Logs](https://user-images.githubusercontent.com/6440106/200621625-01692823-b496-4090-b49d-98c0058d05cd.png)

###
Updates to the integration are provided through CloudFormation template updates. This may upgrade architecture and the Lambda functions.