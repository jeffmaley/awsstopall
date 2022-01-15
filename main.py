"""This script disables IAM user passwords and access keys,
stops running ec2 instances, deletes autoscaling groups, and
adds public blocks to s3 buckets"""

import os
import sys
import logging
import traceback
import json
import boto3


logger = logging.getLogger()
logger.setLevel(logging.INFO)

disable_iam_users = os.environ['DISABLE_IAM_USERS']
stop_ec2_instances = os.environ['STOP_EC2_INSTANCES']
block_s3 = os.environ['BLOCK_S3']
delete_autoscaling_groups = os.environ['DELETE_AUTOSCALING_GROUPS']


def get_regions():
    """Return all active regions"""
    ec2_base = boto3.client('ec2')
    result = ec2_base.describe_regions()
    return result['Regions']


def get_ec2_instances_helper(ec2, next_token):
    """Call AWS GetInstances based on NextToken conditional"""
    if not next_token:
        result = ec2.describe_instances(
                                Filters=[
                                    {
                                        'Name': 'instance-state-name',
                                        'Values': [
                                            'running'
                                        ]
                                    }
                                ],
                                MaxResults=500,
        )
    else:
        result = ec2.describe_instances(
                                Filters=[
                                    {
                                        'Name': 'instance-state-name',
                                        'Values': [
                                            'running'
                                        ]
                                    }
                                ],
                                MaxResults=500,
                                NextToken=next_token
        )
    return result


def get_ec2_instances(ec2):
    """Get running EC2 instances."""
    running_instances = []
    result = get_ec2_instances_helper(ec2, '')
    try:
        running_instances.append(result['Reservations'][0]['Instances'])
    except IndexError:
        pass
    next_token = ''
    try:
        if result['NextToken']:
            old_token = 'old_token'
            while next_token != old_token:
                result = get_ec2_instances_helper(ec2, next_token)
                old_token = next_token
                next_token = result['NextToken']
                running_instances.append(
                                    result['Reservations'][0]['Instances']
                                    )
    except KeyError:
        # No NextToken found so no more records.
        pass
    except Exception as excp: # pylint: disable=broad-except
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(
                                        exception_type,
                                        exception_value,
                                        exception_traceback
                                        )
        err_msg = json.dumps({
            "errorType": exception_type.__name__,
            "errorMessage": str(exception_value),
            "stackTrace": traceback_string
        })
        logger.error(err_msg)
        logger.error(excp)
    return running_instances


def stop_running_ec2_instances(ec2, instance_id):
    """Stop EC2 instance"""
    try:
        logger.info("Stopping instance %s", instance_id)
        ec2.stop_instances(
                    InstanceIds=[instance_id]
        )
    except Exception as excp: # pylint: disable=broad-except
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(
                                        exception_type,
                                        exception_value,
                                        exception_traceback
                                        )
        err_msg = json.dumps({
            "errorType": exception_type.__name__,
            "errorMessage": str(exception_value),
            "stackTrace": traceback_string
        })
        logger.error(err_msg)
        logger.error(excp)


def get_s3_buckets(s3_client):
    """Return list of S3 buckets"""
    result = s3_client.list_buckets()
    return result['Buckets']


def block_s3_public_access(s3_client, bucket):
    """Apply Public Access Block on an S3 bucket"""
    try:
        logger.info("Setting Block Public Access on %s", bucket)
        s3_client.put_public_access_block(
                    Bucket=bucket,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
        )
    except Exception as excp: # pylint: disable=broad-except
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(
                                        exception_type,
                                        exception_value,
                                        exception_traceback
                                        )
        err_msg = json.dumps({
            "errorType": exception_type.__name__,
            "errorMessage": str(exception_value),
            "stackTrace": traceback_string
        })
        logger.error(err_msg)
        logger.error(excp)


def get_autoscaling_groups_helper(autoscaling, next_token):
    """Get AutoScaling Groups based on NextToken"""
    if not next_token:
        result = autoscaling.describe_auto_scaling_groups()
    else:
        result = autoscaling.describe_auto_scaling_groups(
                            NextToken=next_token
        )
    return result


def get_autoscaling_groups(autoscaling):
    """Get AutoScaling Groups"""
    autoscaling_groups = []
    result = get_autoscaling_groups_helper(autoscaling, '')
    autoscaling_groups.append(result['AutoScalingGroups'])
    next_token = ''
    try:
        if result['NextToken']:
            old_token = 'old_token'
            while next_token != old_token:
                result = get_autoscaling_groups_helper(autoscaling, next_token)
                old_token = next_token
                next_token = result['NextToken']
                autoscaling_groups.append(result['AutoScalingGroups'])
    except KeyError:
        # No NextToken found so no more records.
        pass
    except Exception as excp: # pylint: disable=broad-except
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(
                                        exception_type,
                                        exception_value,
                                        exception_traceback
                                        )
        err_msg = json.dumps({
            "errorType": exception_type.__name__,
            "errorMessage": str(exception_value),
            "stackTrace": traceback_string
        })
        logger.error(err_msg)
        logger.error(excp)
    return autoscaling_groups


def delete_autoscaling_group(autoscaling, autoscaling_group):
    """Delete AutoScaling Group"""
    try:
        logger.info("Deleting AutoScalingGroup %s", autoscaling_group)
        autoscaling.delete_auto_scaling_group(
                            AutoScalingGroupName=autoscaling_group,
                            ForceDelete=True
        )
    except Exception as excp: # pylint: disable=broad-except
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(
                                        exception_type,
                                        exception_value,
                                        exception_traceback
                                        )
        err_msg = json.dumps({
            "errorType": exception_type.__name__,
            "errorMessage": str(exception_value),
            "stackTrace": traceback_string
        })
        logger.error(err_msg)
        logger.error(excp)


def get_iam_users_helper(iam, marker):
    """Get IAM users based on Marker"""
    if not marker:
        result = iam.list_users()
    else:
        result = iam.list_users(Marker=marker)
    return result


def get_iam_users(iam):
    """Get all IAM users in account"""
    iam_users = []
    result = get_iam_users_helper(iam, '')
    iam_users.append(result['Users'])
    marker = ''
    try:
        if result['Marker']:
            old_marker = 'old_marker'
            while old_marker != marker:
                result = get_iam_users_helper(iam, marker)
                old_marker = marker
                marker = result['Marker']
                iam_users.append(result['Users'])
    except KeyError:
        # No Marker found so no more records.
        pass
    except Exception as excp: # pylint: disable=broad-except
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(
                                        exception_type,
                                        exception_value,
                                        exception_traceback
                                        )
        err_msg = json.dumps({
            "errorType": exception_type.__name__,
            "errorMessage": str(exception_value),
            "stackTrace": traceback_string
        })
        logger.error(err_msg)
        logger.error(excp)
    return iam_users


def delete_iam_user_profile(iam, iam_user):
    """Delete the password for an IAM user"""
    try:
        logger.info("Disabling password for user %s", iam_user)
        iam.delete_login_profile(
                    UserName=iam_user
        )
    except iam.exceptions.NoSuchEntityException:
        # No LoginProfile found so no password to disable
        logger.info("No LoginProfile found for %s", iam_user)
    except Exception as excp: # pylint: disable=broad-except
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(
                                        exception_type,
                                        exception_value,
                                        exception_traceback
                                        )
        err_msg = json.dumps({
            "errorType": exception_type.__name__,
            "errorMessage": str(exception_value),
            "stackTrace": traceback_string
        })
        logger.error(err_msg)
        logger.error(excp)


def disable_iam_user_access_keys(iam_resource, iam_user):
    """Deactivate the access keys for an IAM user"""
    iam_user_obj = iam_resource.User(iam_user)
    access_keys = iam_user_obj.access_keys.all()
    for access_key in access_keys:
        logger.info("Disabling access key %s for user %s", access_key, iam_user)
        access_key.deactivate()


def process_ec2(region):
    """Parent function for processing EC2"""
    if stop_ec2_instances == 'true':
        ec2_client = boto3.client('ec2', region_name=region['RegionName'])
        running_instances = get_ec2_instances(ec2_client)
        if running_instances:
            for instance in running_instances[0]:
                print(instance['InstanceId'])
                stop_running_ec2_instances(ec2_client, instance['InstanceId'])


def process_autoscaling_groups(region):
    """Parent function for processing AutoScalingGroups"""
    if delete_autoscaling_groups == 'true':
        autoscaling = boto3.client(
                            'autoscaling',
                            region_name=region['RegionName']
                            )
        autoscaling_groups = get_autoscaling_groups(autoscaling)
        if autoscaling_groups:
            for autoscaling_group in autoscaling_groups[0]:
                print(autoscaling_group['AutoScalingGroupName'])
                delete_autoscaling_group(
                    autoscaling,
                    autoscaling_group['AutoScalingGroupName']
                    )

def process_s3():
    """Parent function for processing S3"""
    s3_client = boto3.client('s3')
    if block_s3 == 'true':
        s3_buckets = get_s3_buckets(s3_client)
        if s3_buckets:
            for bucket in s3_buckets:
                print(bucket['Name'])
                block_s3_public_access(s3_client, bucket['Name'])


def process_iam():
    """Parent function for processing IAM"""
    iam_client = boto3.client('iam')
    iam_resource = boto3.resource('iam')
    if disable_iam_users == 'true':
        iam_users = get_iam_users(iam_client)
        if iam_users:
            for iam_user in iam_users[0]:
                print(iam_user['UserName'])
                delete_iam_user_profile(iam_client, iam_user['UserName'])
                disable_iam_user_access_keys(
                    iam_resource,
                    iam_user['UserName']
                    )

def main(event, context):
    """Main entry point
    Process EC2 instances, AutoScaling Groups, S3 buckets, and IAM Users
    """
    regions = get_regions()
    for region in regions:
        logger.info("Processing region %s", region['RegionName'])
        process_ec2(region['RegionName'])
        process_autoscaling_groups(region['RegionName'])

    logger.info("Processing S3")
    process_s3()
    process_iam()


if __name__ == "__main__":
    EVENT = ''
    CONTEXT = ''
    main(EVENT, CONTEXT)
