# awsstopall

## Description

Stop running AWS resources  after a budget limit is reached.

This application performs the following actions when triggered:

* Stop all running EC2 instances in all regions
* Remove all Auto-Scaling groups from all regions
* Block all public access to S3
* Disable all IAM Users' access keys and passwords

## Installation

* Upload the awsstopall-lambda.zip to an S3 bucket
* Run the cloudformation template `awsstopall-cloudformation.yaml` and provide the necessary values.

NOTE: The account you use to deploy must have write access to Billing (https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_billing.html).

## TODO

* Stop RDS
