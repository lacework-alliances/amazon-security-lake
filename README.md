# Lacework FortiCNAPP Amazon Security Lake Integration
![Fortinet-logo-rgb-black-red](https://github.com/user-attachments/assets/99c6a147-2abf-4a32-bf43-a565ca839754)


## Overview
Lacework FortiCNAPP can integrate with Amazon Security Lake, an S3 data data lake that is based on the [OCSF standard](https://schema.ocsf.io/).
Lacework FortiCNAPP integrates as a data source and provides our real-time security findings. These security findings include software and infrastructure-as-code (IaC) vulnerabilities, cloud resource security misconfigurations, and known and unknown security threat behaviors.

## NOTE:
You must have a data lake configured in Amazon Security Lake to use this integration. The integration does not provision the data lake, and the event Lambda will fail when attempting to send Lacework FortiCNAPP events to the custom S3 data source. Please follow the steps described in the following AWS guide to get started:
* https://docs.aws.amazon.com/security-lake/latest/userguide/getting-started.html

## How it Works
![Security Lake](https://github.com/user-attachments/assets/536cf7f9-6f53-4e9a-9112-6cc4db95f4bb)

Lacework FortiCNAPP security findings are sent to Amazon EventBridge and delivered to Amazon SQS queue. A Lambda function receives these security findings from the queue and then transforms them into OCSF format for delivery to the Amazon Security Lake S3 bucket as Parquet formatted files. The Amazon Security Lake Service ingests these files and the Lacework FortiCNAPP security findings.

This integration uses Amazon S3, Lambda, EventBridge, SQS and Cloudwatch AWS Services. You will incur costs due to the use of the services. Costs will vary depending on the size of the environment and the number of security findings found in the environment.

## CloudFormation Deployment
CloudFormation is used to set up the Lacework integration with Security Lake. The CloudFormation template creates the EventBridge rules, IAM permissions, SNS topic, SQS queue, Lambda event transformation function and the Lacework FortiCNAPP outbound security alert channel.

### Prerequisites
* Subscription to Lacework FortiCNAPP. Acquire through [AWS Marketplace listing](https://aws.amazon.com/marketplace/pp/prodview-uv2dct6bigr54?sr=0-1&ref_=beagle&applicationId=AWSMPContessa).
* Administrator access to a Lacework FortiCNAPP instance
* [FortiCNAPP Admin API Key and Secret](https://docs.lacework.com/api/api-access-keys-and-tokens)
  

### Create the Amazon Security Lake Custom Source for Lacework FortiCNAPP Security Findings
Do the following:

1. Open the Security Lake console at https://console.aws.amazon.com/securitylake/.
2. Select the region where you want to create the custom source, in the upper-right corner of the page.
3. Choose Custom sources in the navigation pane, and then choose Create custom source.
4. In the Custom source details section, enter **"lacework"** for your custom source name. Then, select the **Security Finding OCSF** event class.
5. Enter the AWS account ID from which the Lacework FortiCNAPP Amazon Security Lake Alert Channel will be deployed. This account will write logs and events to the data lake.
6. For the AWS account with permissions to write logs and events to the data lake using the Lacework FortiCNAPP Amazon Security Lake Alert Channel, enter the AWS account ID and External ID. The External ID is a random alphanumeric identifier that is used to prevent unauthorized access to your AWS resources.
7. For Service Access, create a new IAM role or use an existing IAM role that gives Security Lake permission to invoke the AWS Glue crawler.
8. Choose Create.
9. After the custom source is created, take note of the Amazon Security Lake S3 location.


### Deploy the CloudFormation Template

1. Click on the following Launch Stack button to go to your CloudFormation console and launch the template.

   [![Launch](https://user-images.githubusercontent.com/6440106/153987820-e1f32423-1e69-416d-8bca-2ee3a1e85df1.png)](https://console.aws.amazon.com/cloudformation/home?#/stacks/create/review?templateURL=https://lacework-alliances.s3.us-west-2.amazonaws.com/lacework-amazon-security-lake/templates/amazon-security-lake-integration.yml)

   For most deployments, you only need the Basic Configuration parameters.
   ![basic](https://github.com/user-attachments/assets/a7643a48-1d17-4d44-8f98-e65d1a7d8fd1)
   
2. Specify the following Basic Configuration parameters:
    * Enter a **Stack name** for the stack.
    * Enter the **Security Lake S3 Bucket Name**.
    * Enter the **Security Lake Role ARN**.
    * Enter the **Security Lake Role External ID**.
    * Enter **Your Lacework URL**.
    * If your Lacework instance has the Organization feature enabled, enter the **Lacework Sub-Account Name**. Otherwise, leave this field blank.
    * Enter your **Lacework Access Key ID** and **Lacework Secret Key** that you copied from your API Keys file. See [here](https://docs.lacework.com/console/generate-api-access-keys-and-tokens).
     
3. Click **Next** through to your stack **Review**.
4. Accept the AWS CloudFormation terms and click **Create stack**.
5. Upon successful stack deployment, ensure the Lambda Event Function role ARN is added to the Amazon Security Lake role trust policy.
If it has not been automatically added, use the following procedure to configure it:

   **a**. In the AWS console, navigate to **Lambda** and click the Lambda function with the name stack-name-
   LaceworkAmazonSecurityLakeEventFunction-xxxx. Copy the ARN.

   **b**. In **IAM > Roles**, click the role that was created for your security lake configuration. Click **Trust relationships** >
   **Edit trust policy**.

   **c**. Add the event function ARN in the following format:

 ```
   {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::111122223333:root",
                    "arn:aws:iam::444455556666:role/lw-seclake-LaceworkAmazonSecurityLakeEventFunctionR-aBcDeFg"
                ]
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "<external id>"
                }
            }
        }
    ]
}
```

### Troubleshooting
Troubleshooting this integration can be done by monitoring the CloudWatch logs for two Lambda functions. One Lambda function is responsible for some of the initial setup during the CloudFormation deployment. The second Lambda function transforms Lacework security alerts to the OCSF security findings for Security Lake.

#### Initial Setup Troubleshooting
Some initial set up during the CloudFormation deployment is handled by a Lambda function **_stack-name_-LaceworkAmazonSecurityLakeSetupFunction-_xxxx_**. Specifically, it configures the Alert Channel and Alert Rules that are required to send Lacework Security Alerts to the second Lambda function for transformation into OCSF and Amazon Security Lake.
To investigate any issues, use the following steps:

1. Go to Lambda in your AWS management console.
2. Find the Lambda function with the name **_stack-name_-LaceworkAmazonSecurityLakeSetupFunction-_xxxx_**.
3. Click the **Monitor** tab.
4. Click the button **View logs in CloudWatch** to launch CloudWatch into a new tab.
5. View the **Log stream** debug for errors.

![setup-func](https://github.com/user-attachments/assets/86a98d1f-ad37-4f40-8e57-164cbfd03f1f)


#### Security Findings Event Troubleshooting
If there are issues with Lacework FortiCNAPP Security Alerts being transformed to OCSF and Amazon Security Lake, investigate the Lambda function **_stack-name_-LaceworkAmazonSecurityLakeEventFunction-_xxxx_**. It transforms Lacework Security alerts into OCSF Security Findings format and delivers these in Parquet file format to the Security Lake S3 bucket.
To investigate any issues, use the following steps:

1. Go to Lambda in your AWS management console.
2. Find the Lambda function with the name **_stack-name_-LaceworkAmazonSecurityLakeEventFunction-_xxxx_**.
3. Click the **Monitor** tab.
4. Click the button **View logs in CloudWatch** to launch CloudWatch into a new tab.
5. View the **Log stream** debug for errors.

![seclake-cw-log](https://github.com/user-attachments/assets/2e783783-b0e8-4143-a348-5eba836c7817)

### Updates
Updates to the integration are provided through CloudFormation template updates. This may upgrade architecture and the Lambda functions.
