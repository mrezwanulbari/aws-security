-- =============================================================================
-- CloudTrail Athena Query: IAM Configuration Changes
-- =============================================================================
-- Description: Tracks all IAM changes including user creation, policy
--              modifications, and role assumption for security auditing.
-- =============================================================================

SELECT
    eventTime,
    eventName,
    userIdentity.arn AS actor,
    sourceIPAddress,
    requestParameters,
    responseElements,
    errorCode
FROM
    cloudtrail_logs
WHERE
    eventSource = 'iam.amazonaws.com'
    AND eventName IN (
        'CreateUser', 'DeleteUser',
        'CreateRole', 'DeleteRole',
        'CreatePolicy', 'DeletePolicy',
        'AttachUserPolicy', 'DetachUserPolicy',
        'AttachRolePolicy', 'DetachRolePolicy',
        'PutUserPolicy', 'DeleteUserPolicy',
        'PutRolePolicy', 'DeleteRolePolicy',
        'CreateAccessKey', 'DeleteAccessKey',
        'UpdateAccessKey',
        'CreateLoginProfile', 'UpdateLoginProfile',
        'AddUserToGroup', 'RemoveUserFromGroup',
        'UpdateAssumeRolePolicy'
    )
    AND eventTime >= date_add('day', -7, now())
ORDER BY
    eventTime DESC;
