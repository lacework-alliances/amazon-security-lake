# AWS Moose

![Lacework](https://user-images.githubusercontent.com/6440106/152378397-90c862e9-19fb-4427-96d0-02ca6c87f4dd.png)

## Overview
This repository contains Lacework's integration with AWS Moose, a security data lake that is based on the [OCSF standard](https://schema.ocsf.io/).
Lacework integrates with “AWS MOOSE'' as a data source and provides our security findings that include software vulnerabilities, misconfigurations, and known and unknown threats.

## Architecture
![moose](https://user-images.githubusercontent.com/6440106/200464957-6fd1df7d-e3ed-4e86-994b-60dd0bc0dbc0.png)

## CloudFormation Deployment
CloudFormation is used to deploy the Lacework integration with AWS Moose. The CloudFormation template creates the EventBridge rules, IAM permissions, SNS topic, SQS queue, Lambda event transformation function and the Lacework outbound security alert channel.

### Prerequisites
* Access to a Lacework Instance
* [Lacework Admin API Key and Secret](https://docs.lacework.com/api/api-access-keys-and-tokens)

### Deploy the CloudFormation Template

1. Click on the following Launch Stack button to go to your CloudFormation console and launch the template.

   [![Launch](https://user-images.githubusercontent.com/6440106/153987820-e1f32423-1e69-416d-8bca-2ee3a1e85df1.png)](https://console.aws.amazon.com/cloudformation/home?#/stacks/create/review?templateURL=https://lacework-alliances.s3.us-west-2.amazonaws.com/lacework-moose/templates/moose-integration.yml)

   For most deployments, you only need the Basic Configuration parameters.
   ![basic](https://user-images.githubusercontent.com/6440106/200466378-c7940e9a-128a-40c3-8281-03cadea31561.png)
   Specify the following Basic Configuration parameters:
    * Enter a **Stack name** for the stack.
    * Enter the **Moose S3 Bucket Name**.
    * Enter **Your Lacework URL**.
    * Enter your **Lacework Access Key ID** and **Lacework Secret Key** that you copied from your API Keys file. See [here](https://docs.lacework.com/console/generate-api-access-keys-and-tokens).
3. Click **Next** through to your stack **Review**.
4. Accept the AWS CloudFormation terms and click **Create stack**.

