-- =============================================================================
-- CloudTrail Athena Query: Unauthorized API Calls
-- =============================================================================
-- Description: Identifies IAM principals generating high volumes of AccessDenied
--              errors, which may indicate privilege escalation attempts.
-- =============================================================================

SELECT
    userIdentity.arn AS principal_arn,
    userIdentity.type AS identity_type,
    sourceIPAddress,
    COUNT(*) AS denied_count,
    array_agg(DISTINCT eventName) AS denied_actions,
    array_agg(DISTINCT errorCode) AS error_codes,
    MIN(eventTime) AS first_seen,
    MAX(eventTime) AS last_seen
FROM
    cloudtrail_logs
WHERE
    errorCode IN ('AccessDenied', 'UnauthorizedAccess', 'Client.UnauthorizedAccess')
    AND eventTime >= date_add('hour', -24, now())
GROUP BY
    userIdentity.arn,
    userIdentity.type,
    sourceIPAddress
HAVING
    COUNT(*) > 10
ORDER BY
    denied_count DESC
LIMIT 50;
