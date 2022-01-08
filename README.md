# awsstopall

## Description

Stop running AWS resources  after a budget limit is reached.

This application performs the following actions when triggered:

* Stop all running EC2 instances in all regions
* Remove all Auto-Scaling groups
* Block all public access to S3
* Disable all IAM Users and Roles

## TODO

* Stop RDS
