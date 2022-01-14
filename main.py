import boto3
import sys
import logging
import traceback
import json
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

disable_iam_users = os.environ['DISABLE_IAM_USERS']
stop_ec2_instances = os.environ['STOP_EC2_INSTANCES']
block_s3 = os.environ['BLOCK_S3']
delete_autoscaling_groups = os.environ['DELETE_AUTOSCALING_GROUPS']

def get_regions(ec2):
    result = ec2.describe_regions()
    return result['Regions']


def get_ec2_instances_helper(ec2, next_token):
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
                running_instances.append(result['Reservations'][0]['Instances'])
    except KeyError:
        # No NextToken
        pass
    except Exception as e:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(exception_type, exception_value, exception_traceback)
        err_msg = json.dumps({
            "errorType": exception_type.__name__,
            "errorMessage": str(exception_value),
            "stackTrace": traceback_string
        })
        logger.error(err_msg)
    return running_instances

def stop_ec2_instances(ec2, instance_id):
    result = ec2.stop_instances(
                InstanceIds=[instance_id]
    )

def get_s3_buckets(s3):
    result = s3.list_buckets()
    return result['Buckets']

def block_s3_public_access(s3, bucket):
    result = s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
    )

def get_autoscaling_groups_helper(autoscaling, next_token):
    if not next_token:
        result = autoscaling.describe_auto_scaling_groups()
    else:
        result = autoscaling.describe_auto_scaling_groups(
                            NextToken=next_token
        )
    return result

def get_autoscaling_groups(autoscaling):
    autoscaling_groups = []
    result = get_autoscaling_groups_helper(autoscaling, '')
    autoscaling_groups.append(result['AutoScalingGroups'])
    next_token = ''
    try:
        if result['NextToken']:
            old_token = 'old_token'
            while next_token != old_token:
                result = get_autoscaling_groups(autoscaling, next_token)
                old_token = next_token
                next_token = result['NextToken']       
                autoscaling_groups.append(result['AutoScalingGroups'])
    except KeyError:
        # No NextToken
        pass
    except Exception as e:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(exception_type, exception_value, exception_traceback)
        err_msg = json.dumps({
            "errorType": exception_type.__name__,
            "errorMessage": str(exception_value),
            "stackTrace": traceback_string
        })
        logger.error(err_msg)    
    return autoscaling_groups

def delete_autoscaling_group(autoscaling, autoscaling_group):
    result = autoscaling.delete_auto_scaling_group(
                        AutoScalingGroupName=autoscaling_group,
                        ForceDelete=True
    )

def get_iam_users_helper(iam, marker):
    if not marker:
        result = iam.list_users()
    else:
        result = iam.list_users(Marker=marker)
    return result

def get_iam_users(iam):
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
        # No Marker
        pass
    except Exception as e:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_string = traceback.format_exception(exception_type, exception_value, exception_traceback)
        err_msg = json.dumps({
            "errorType": exception_type.__name__,
            "errorMessage": str(exception_value),
            "stackTrace": traceback_string
        })
        logger.error(err_msg)                
    return iam_users

def delete_iam_user_profile(iam, iam_user):
    result = ''
    try:
        result = iam.delete_login_profile(
                    UserName=iam_user
        )
    except iam.exceptions.NoSuchEntityException:
        # No LoginProfile found
        result = f'No LoginProfile found for {iam_user}'
    logger.info(result)
    return

def disable_iam_user_access_keys(iam_resource, iam_user):
    iam_user_obj = iam_resource.User(iam_user)
    access_keys = iam_user_obj.access_keys.all()
    for access_key in access_keys:
        print(access_key)
        access_key.deactivate()
    return

def main():
    ec2_base = boto3.client('ec2')
    s3 = boto3.client('s3')
    iam = boto3.client('iam')
    iam_resource = boto3.resource('iam')

    regions = get_regions(ec2_base)
    for region in regions:
        print(region['RegionName'])
        ec2 = boto3.client('ec2', region_name=region['RegionName'])
        autoscaling = boto3.client('autoscaling', region_name=region['RegionName'])
        running_instances = get_ec2_instances(ec2)
        if running_instances:
            for instance in running_instances[0]:
                print(instance['InstanceId'])
                stop_ec2_instances(ec2, instance['InstanceId'])

        autoscaling_groups = get_autoscaling_groups(autoscaling)
        if autoscaling_groups:
            for autoscaling_group in autoscaling_groups[0]:
                print(autoscaling_group['AutoScalingGroupName'])
                delete_autoscaling_group(autoscaling, autoscaling_group['AutoScalingGroupName'])

    s3_buckets = get_s3_buckets(s3)
    if s3_buckets:
        for bucket in s3_buckets:
            print(bucket['Name'])
            block_s3_public_access(s3, bucket['Name'])

    iam_users = get_iam_users(iam)
    if iam_users:
        for iam_user in iam_users[0]:
            print(iam_user['UserName'])
            delete_iam_user_profile(iam, iam_user['UserName'])
            disable_iam_user_access_keys(iam_resource, iam_user['UserName'])
    return

if __name__ == "__main__":
    main()