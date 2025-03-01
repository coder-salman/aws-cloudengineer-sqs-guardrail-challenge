import json
import os
import boto3
import logging
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
sqs_client = boto3.client('sqs')
ec2_client = boto3.client('ec2')
kms_client = boto3.client('kms')
sns_client = boto3.client('sns')

# Get SNS topic ARN from environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

# Required tags for SQS queues
REQUIRED_TAGS = ['Name', 'CreatedBy', 'CostCenter']


def lambda_handler(event, context):
    """
    Lambda function to validate SQS queue security configurations.
    
    Parameters:
    event (dict): Event data from EventBridge
    context (LambdaContext): Lambda runtime information
    
    Returns:
    dict: Response containing validation results
    """
    try:
        logger.info("Received event: %s", json.dumps(event))
        
        # Extract queue details from the event
        detail = event.get('detail', {})
        if not detail:
            logger.warning("Event does not contain required detail")
            return {'statusCode': 400, 'body': 'Invalid event format'}
        
        request_parameters = detail.get('requestParameters', {})
        queue_name = request_parameters.get('queueName')
        
        if not queue_name:
            logger.warning("Queue name not found in event")
            return {'statusCode': 400, 'body': 'Queue name not found'}
        
        # Get the queue URL
        try:
            queue_url_response = sqs_client.get_queue_url(QueueName=queue_name)
            queue_url = queue_url_response['QueueUrl']
        except ClientError as e:
            logger.error("Error getting queue URL: %s", e)
            return {'statusCode': 404, 'body': f'Queue not found: {queue_name}'}
        
        # Perform compliance checks
        validation_results = validate_queue(queue_url, queue_name)
        
        # If any validation failed, send alert
        if not all(validation_results.values()):
            send_alert(queue_name, validation_results)
        
        return {
            'statusCode': 200,
            'queueName': queue_name,
            'validationResults': validation_results,
            'compliant': all(validation_results.values())
        }
        
    except Exception as e:
        logger.error("Error in lambda_handler: %s", e)
        return {'statusCode': 500, 'body': str(e)}


def validate_queue(queue_url, queue_name):
    """
    Validates SQS queue against security requirements.
    
    Parameters:
    queue_url (str): URL of the SQS queue
    queue_name (str): Name of the SQS queue
    
    Returns:
    dict: Validation results for each check
    """
    results = {
        'vpc_endpoint_exists': check_vpc_endpoint_exists(),
        'encryption_enabled': False,
        'using_cmk': False,
        'has_required_tags': False,
        'has_dlq_configured': False
    }
    
    try:
        # Get queue attributes
        attributes = sqs_client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=['All']
        )['Attributes']
        
        # Check 1: Encryption enabled
        kms_master_key_id = attributes.get('KmsMasterKeyId')
        results['encryption_enabled'] = kms_master_key_id is not None
        
        # Check 2: Using CMK instead of AWS-managed key
        if kms_master_key_id:
            results['using_cmk'] = check_is_customer_managed_key(kms_master_key_id)
        
        # Check 3: Required tags
        results['has_required_tags'] = check_required_tags(queue_url)
        
        # Check 4: DLQ configured
        results['has_dlq_configured'] = 'RedrivePolicy' in attributes
        
        logger.info("Validation results for queue %s: %s", queue_name, results)
    except Exception as e:
        logger.error("Error validating queue %s: %s", queue_name, e)
    
    return results


def check_vpc_endpoint_exists():
    """
    Checks if a VPC endpoint for SQS exists.
    
    Returns:
    bool: True if VPC endpoint exists, False otherwise
    """
    try:
        endpoints = ec2_client.describe_vpc_endpoints(
            Filters=[
                {
                    'Name': 'service-name',
                    'Values': [f'com.amazonaws.{boto3.session.Session().region_name}.sqs']
                }
            ]
        )
        return len(endpoints.get('VpcEndpoints', [])) > 0
    except Exception as e:
        logger.error("Error checking VPC endpoints: %s", e)
        return False


def check_is_customer_managed_key(key_id):
    """
    Checks if the provided KMS key is customer-managed.
    
    Parameters:
    key_id (str): KMS key ID or ARN
    
    Returns:
    bool: True if key is customer-managed, False if AWS-managed
    """
    try:
        key_info = kms_client.describe_key(KeyId=key_id)
        # AWS-managed keys have AWS_MANAGED in the description or specific AWS service ARNs
        is_customer_managed = not key_info.get('KeyMetadata', {}).get('Description', '').startswith('Default')
        return is_customer_managed
    except Exception as e:
        logger.error("Error checking KMS key: %s", e)
        return False


def check_required_tags(queue_url):
    """
    Checks if the SQS queue has all required tags.
    
    Parameters:
    queue_url (str): URL of the SQS queue
    
    Returns:
    bool: True if all required tags are present, False otherwise
    """
    try:
        tags_response = sqs_client.list_queue_tags(QueueUrl=queue_url)
        tags = tags_response.get('Tags', {})
        
        # Check if all required tags are present
        for tag in REQUIRED_TAGS:
            if tag not in tags:
                logger.warning("Missing required tag: %s", tag)
                return False
        
        return True
    except Exception as e:
        logger.error("Error checking queue tags: %s", e)
        return False


def send_alert(queue_name, validation_results):
    """
    Sends an alert to the configured SNS topic when validation fails.
    
    Parameters:
    queue_name (str): Name of the non-compliant SQS queue
    validation_results (dict): Results of validation checks
    """
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not configured, skipping alert")
        return
    
    try:
        # Prepare alert message
        failed_checks = [check for check, result in validation_results.items() if not result]
        message = {
            'subject': f'SQS Compliance Alert: {queue_name}',
            'message': (
                f'SQS queue {queue_name} failed the following compliance checks:\n'
                f'{json.dumps(failed_checks, indent=2)}\n\n'
                f'Please remediate these issues immediately to ensure security compliance.'
            )
        }
        
        # Send SNS notification
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=message['subject'],
            Message=message['message']
        )
        
        logger.info("Alert sent to SNS topic: %s", SNS_TOPIC_ARN)
    except Exception as e:
        logger.error("Error sending alert: %s", e)