"""
AWS Security Group Auto-Remediation Lambda
============================================
Automatically revokes overly permissive security group rules
(0.0.0.0/0 ingress) when detected by AWS Config or EventBridge.

Triggered by: EventBridge rule on EC2 Security Group change events
"""

import json
import logging
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client('ec2')
sns_client = boto3.client('sns')

# Configuration
ALLOWED_PUBLIC_PORTS = [80, 443]  # Ports allowed to be public
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:ACCOUNT_ID:security-alerts'


def lambda_handler(event, context):
    """Process security group change events and remediate if needed."""
    logger.info(f"Received event: {json.dumps(event)}")

    detail = event.get('detail', {})
    event_name = detail.get('eventName', '')

    if event_name not in ['AuthorizeSecurityGroupIngress', 'ModifySecurityGroupRules']:
        logger.info(f"Skipping event: {event_name}")
        return

    request_params = detail.get('requestParameters', {})
    group_id = request_params.get('groupId', '')

    if not group_id:
        logger.warning("No security group ID found in event")
        return

    # Check for overly permissive rules
    response = ec2_client.describe_security_groups(GroupIds=[group_id])

    if not response['SecurityGroups']:
        logger.warning(f"Security group {group_id} not found")
        return

    sg = response['SecurityGroups'][0]
    remediated_rules = []

    for permission in sg.get('IpPermissions', []):
        from_port = permission.get('FromPort', 0)
        to_port = permission.get('ToPort', 65535)

        for ip_range in permission.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                if from_port not in ALLOWED_PUBLIC_PORTS:
                    # Revoke the overly permissive rule
                    try:
                        ec2_client.revoke_security_group_ingress(
                            GroupId=group_id,
                            IpPermissions=[{
                                'IpProtocol': permission.get('IpProtocol', 'tcp'),
                                'FromPort': from_port,
                                'ToPort': to_port,
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                            }]
                        )
                        remediated_rules.append({
                            'port': from_port,
                            'protocol': permission.get('IpProtocol', 'tcp'),
                            'cidr': '0.0.0.0/0'
                        })
                        logger.info(
                            f"Revoked rule: {group_id} port {from_port} "
                            f"from 0.0.0.0/0"
                        )
                    except Exception as e:
                        logger.error(f"Failed to revoke rule: {e}")

    if remediated_rules:
        # Send notification
        actor = detail.get('userIdentity', {}).get('arn', 'Unknown')
        message = (
            f"SECURITY AUTO-REMEDIATION\n\n"
            f"Security Group: {group_id}\n"
            f"SG Name: {sg.get('GroupName', 'N/A')}\n"
            f"Actor: {actor}\n"
            f"Rules Revoked: {json.dumps(remediated_rules, indent=2)}\n\n"
            f"Action: Overly permissive ingress rules (0.0.0.0/0) on "
            f"non-standard ports were automatically revoked."
        )

        try:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f'[AUTO-REMEDIATION] SG {group_id} - Public Access Revoked',
                Message=message
            )
        except Exception as e:
            logger.error(f"Failed to send SNS notification: {e}")

    return {
        'statusCode': 200,
        'body': json.dumps({
            'group_id': group_id,
            'rules_remediated': len(remediated_rules)
        })
    }
