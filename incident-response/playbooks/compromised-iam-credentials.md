# Incident Response Playbook: Compromised IAM Credentials

## Classification
- **Severity**: High/Critical
- **Category**: Unauthorized Access
- **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)

## Detection Sources
- AWS GuardDuty: `UnauthorizedAccess:IAMUser/MaliciousIPCaller`
- AWS CloudTrail: Unusual API calls, impossible travel
- AWS Security Hub: IAM credential findings
- SIEM: Anomalous authentication patterns

## Phase 1: Detection & Triage (0-15 minutes)

### Immediate Assessment
1. **Identify the compromised principal**
   ```bash
   # Get recent activity for the suspected user
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=Username,AttributeValue=<username> \
     --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
     --max-results 50
   ```

2. **Determine scope of access**
   ```bash
   # List user's policies
   aws iam list-attached-user-policies --user-name <username>
   aws iam list-user-policies --user-name <username>
   aws iam list-groups-for-user --user-name <username>
   ```

3. **Check for active access keys**
   ```bash
   aws iam list-access-keys --user-name <username>
   ```

## Phase 2: Containment (15-60 minutes)

### Immediate Actions

1. **Disable compromised access keys**
   ```bash
   aws iam update-access-key \
     --user-name <username> \
     --access-key-id <key-id> \
     --status Inactive
   ```

2. **Attach deny-all inline policy**
   ```bash
   aws iam put-user-policy \
     --user-name <username> \
     --policy-name EmergencyDenyAll \
     --policy-document '{
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": "*",
         "Resource": "*"
       }]
     }'
   ```

3. **Invalidate active sessions**
   ```bash
   # The deny-all policy above handles this for future API calls
   # For console sessions, delete login profile
   aws iam delete-login-profile --user-name <username>
   ```

## Phase 3: Investigation (1-4 hours)

### CloudTrail Analysis
```sql
-- Athena query for all actions by compromised principal
SELECT eventTime, eventName, eventSource, sourceIPAddress,
       userAgent, requestParameters, responseElements, errorCode
FROM cloudtrail_logs
WHERE userIdentity.arn = 'arn:aws:iam::ACCOUNT:user/USERNAME'
  AND eventTime >= '2024-01-14T00:00:00Z'
ORDER BY eventTime;
```

### Key Investigation Questions
- [ ] What was the initial access vector?
- [ ] Were new credentials or users created?
- [ ] Were any resources modified or created?
- [ ] Was data accessed or exfiltrated?
- [ ] Were other accounts or roles compromised?
- [ ] Was CloudTrail or GuardDuty disabled?

## Phase 4: Remediation

1. **Rotate all credentials** (new access keys, passwords)
2. **Remove any unauthorized resources** (EC2 instances, IAM users, etc.)
3. **Review and tighten IAM policies**
4. **Enable MFA if not already enabled**
5. **Update security group rules if modified**

## Phase 5: Post-Incident

1. Document timeline and root cause
2. Update detection rules with new IOCs
3. Conduct post-incident review meeting
4. Update runbooks based on lessons learned
