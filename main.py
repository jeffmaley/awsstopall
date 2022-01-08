import boto3
import sys
import logging
import traceback
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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
    running_instances.append(result['Reservations'][0]['Instances'])
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

def main():
    ec2 = boto3.client('ec2')
    autoscaling = boto3.client('autoscaling')
    s3 = boto3.client('s3')

    running_instances = get_ec2_instances(ec2)
    for instance in running_instances[0]:
        print(instance['InstanceId'])
        stop_ec2_instances(ec2, instance['InstanceId'])

    s3_buckets = get_s3_buckets(s3)
    for bucket in s3_buckets:
        print(bucket['Name'])
        #block_s3_public_access(s3, bucket['Name'])

    autoscaling_groups = get_autoscaling_groups(autoscaling)
    for autoscaling_group in autoscaling_groups:
        delete_autoscaling_group(autoscaling, autoscaling_group)
    return

if __name__ == "__main__":
    main()