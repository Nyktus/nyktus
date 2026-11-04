# AWS: IAM role that grants nothing

An IAM role with a name that an intruder wants to use, such as `deploy-admin`, that trusts the principals of your own account and has no permissions at all. An intruder who has taken over an identity lists the roles and tries to assume the one that sounds powerful. CloudTrail records the attempt, whether AWS permits it or not, and an EventBridge rule forwards the record to the URL of a honeytoken with a `POST`. The alert says that the role was assumed or that someone tried. The identity and the address of the caller are in the start of the request body that the honeytoken keeps, not in the alert: the address of the event itself is that of the AWS service that sends the webhook.

The commands are for a shell such as bash or zsh, with the AWS CLI version 2 and an identity that may create IAM roles and EventBridge rules. They were checked against the documentation of the AWS CLI, EventBridge and CloudTrail, not run against an account.

## What the bait does in the account

- The role trusts the root of your account, which means that every identity of the account that is allowed to call `sts:AssumeRole` for it can assume it. The role itself holds no policy, no permission boundary and no inline policy, so a session of the role can do nothing.
- Nothing else in the account changes.
- Do not attach a policy to the role later. A role with permissions is no longer a bait.
- Identities with broad rights, such as administrators and automation, can assume the role. If one of your own tools assumes every role it finds, it raises the alert.

## What it needs

1. **A trail that logs management events**, including read events. CloudTrail sends events to EventBridge only while a trail is logging. Check it as in step 1.
2. **A rule in every region where a call can land.** CloudTrail records an event in the region it was made in. A call to the global endpoint of the security token service is recorded in `us-east-1`; a call to a regional endpoint, which the AWS CLI version 2 uses, in the region that the intruder configured. Create the rule in `us-east-1` and in every region that you use, and accept the gap for the others, see Limits.
3. **The URL of the honeytoken**, `Honeytoken-URL`. It stands in the API destination in your account. Treat it as a secret: whoever knows it can send forged events, and whoever may read EventBridge resources can find it.

## Step 1: check the trail

```bash
aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,IncludeGlobalServiceEvents,HasCustomEventSelectors]' --output table
aws cloudtrail get-trail-status --name TRAIL_NAME --query IsLogging
```

You need a trail with `IsLogging` true that is multi-region and includes global service events. If `HasCustomEventSelectors` is true, look at them with `aws cloudtrail get-event-selectors --trail-name TRAIL_NAME`: `IncludeManagementEvents` must be true and `ReadWriteType` must be `All`. A trail with advanced event selectors is shown in the console. If you have no trail, create one in the CloudTrail console (Trails, Create trail) and keep management events on, read and write. The console also creates the bucket for the log files. CloudTrail delivers the first copy of the management events at no charge, but the storage in S3 costs.

## Step 2: create the role

```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
aws iam create-role --role-name deploy-admin --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::$ACCOUNT:root\"},\"Action\":\"sts:AssumeRole\"}]}"
aws iam list-attached-role-policies --role-name deploy-admin
aws iam list-role-policies --role-name deploy-admin
```

The two `list` commands must return empty lists. Choose a name that fits your roles and that an intruder wants: names of deployment, backup and administration work well.

## Step 3: connection, API destination and role for the rule

Set the region. Use the region of your workloads first; step 5 says when to repeat for another region.

```bash
REGION=eu-central-1
KEY=$(aws secretsmanager get-random-password --region "$REGION" --password-length 24 --exclude-punctuation --query RandomPassword --output text)
CONN_ARN=$(aws events create-connection --region "$REGION" --name audit-notify-role-conn --authorization-type API_KEY --auth-parameters "{\"ApiKeyAuthParameters\":{\"ApiKeyName\":\"x-api-key\",\"ApiKeyValue\":\"$KEY\"}}" --query ConnectionArn --output text)
DEST_ARN=$(aws events create-api-destination --region "$REGION" --name audit-notify-role-dest --connection-arn "$CONN_ARN" --invocation-endpoint 'Honeytoken-URL' --http-method POST --invocation-rate-limit-per-second 5 --query ApiDestinationArn --output text)
```

EventBridge demands a connection with an authorization, which the honeytoken ignores, and keeps the key in a secret of Secrets Manager that it manages. The limit of five requests a second keeps a burst of calls from becoming a burst of requests; EventBridge retries what it could not deliver. The role for the rule is global, so you create it once. It may do nothing but invoke this destination, in any region:

```bash
aws iam create-role --role-name audit-notify-role-invoke --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam put-role-policy --role-name audit-notify-role-invoke --policy-name invoke --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"events:InvokeApiDestination\",\"Resource\":\"arn:aws:events:*:$ACCOUNT:api-destination/audit-notify-role-dest/*\"}]}"
```

## Step 4: the rule

The rule matches every attempt to assume the role, by its ARN. EventBridge counts `AssumeRole` among the read-only management events, and these reach a rule only in the state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`, which only the AWS CLI and CloudFormation can set.

```bash
cat > pattern.json <<EOF
{"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["sts.amazonaws.com"],"eventName":["AssumeRole"],"requestParameters":{"roleArn":["arn:aws:iam::$ACCOUNT:role/deploy-admin"]}}}
EOF
aws events put-rule --region "$REGION" --name audit-notify-role-rule --state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS --event-pattern file://pattern.json
```

The target sends only what you need, so that the request body stays well below the 4096 bytes that the honeytoken keeps. A complete CloudTrail record would not fit.

```bash
cat > targets.json <<EOF
[{"Id":"1","Arn":"$DEST_ARN","RoleArn":"arn:aws:iam::$ACCOUNT:role/audit-notify-role-invoke","InputTransformer":{"InputPathsMap":{"eventName":"\$.detail.eventName","sourceIPAddress":"\$.detail.sourceIPAddress","userAgent":"\$.detail.userAgent","userArn":"\$.detail.userIdentity.arn","userType":"\$.detail.userIdentity.type","accountId":"\$.detail.userIdentity.accountId","region":"\$.detail.awsRegion","time":"\$.time"},"InputTemplate":"{\"eventName\":<eventName>,\"sourceIPAddress\":<sourceIPAddress>,\"userAgent\":<userAgent>,\"userArn\":<userArn>,\"userType\":<userType>,\"accountId\":<accountId>,\"region\":<region>,\"time\":<time>}"}}]
EOF
aws events put-targets --region "$REGION" --rule audit-notify-role-rule --targets file://targets.json
rm pattern.json targets.json
```

`put-targets` reports `FailedEntryCount`, which must be 0. If it says that the role cannot be assumed, wait a few seconds after creating the role and repeat the command.

## Step 5: more regions

Repeat step 3 without the role for the rule, then step 4, for `us-east-1` and for every other region you use: set `REGION` and run the commands again. API destinations exist only in some regions; the documentation of EventBridge lists them.

## Placing the bait

The role is found by listing the roles of the account, so it needs no file. To make it found sooner, mention its name where the people of the story would: in a deployment script (`aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/deploy-admin`), a profile of the AWS CLI with a `role_arn` or a ticket. Record where you did it in the scenario.

## Testing

With your own identity, try to assume the role. Your identity may or may not be allowed to; both are recorded:

```bash
aws sts assume-role --region "$REGION" --role-arn arn:aws:iam::$ACCOUNT:role/deploy-admin --role-session-name test --query AssumedRoleUser.Arn --output text
```

CloudTrail delivers an event within about five minutes of the call on average, which AWS does not guarantee. Then the scenario shows an incident, and the event holds a body like this:

```json
{"eventName":"AssumeRole","sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.x ...","userArn":"arn:aws:sts::123456789012:assumed-role/NAME/SESSION","userType":"AssumedRole","accountId":"123456789012","region":"eu-central-1","time":"2026-01-01T10:00:00Z"}
```

Close the incident after the test.

## Removing

```bash
aws events remove-targets --region "$REGION" --rule audit-notify-role-rule --ids 1
aws events delete-rule --region "$REGION" --name audit-notify-role-rule
aws events delete-api-destination --region "$REGION" --name audit-notify-role-dest
aws events delete-connection --region "$REGION" --name audit-notify-role-conn
aws iam delete-role-policy --role-name audit-notify-role-invoke --policy-name invoke
aws iam delete-role --role-name audit-notify-role-invoke
aws iam delete-role --role-name deploy-admin
```

Run the first four for every region. Delete the roles once.

## Limits

- **Without a trail that logs, nothing arrives.** If someone stops the trail or narrows its selectors, the alert stops without a sign.
- **Regions.** An attempt that lands in a region without a rule is not reported. An intruder who uses the global endpoint of the security token service lands in `us-east-1`; one who uses a regional endpoint lands where they configured it.
- **Only the attempt, not the use.** Assuming the role gives the intruder nothing, so there is nothing further to see.
- **Delay.** Minutes, not seconds.
- **Retries.** EventBridge sends a request again when it does not see success in time, so the same call can be reported twice. The honeytoken answers every request alike.
- **The alert names the honeytoken, not the caller.** The address of the event is that of the AWS service that sends the webhook. The caller, its address and its user agent are only in the start of the body, which the console shows as text of an attacker and which appears in no alert.
- **Your own tools.** Anything of yours that tries to assume the role, including you, raises the alert.
- **Visible to those who look.** An intruder with read access to IAM sees a role without permissions, and one with read access to EventBridge sees the destination with its URL.
