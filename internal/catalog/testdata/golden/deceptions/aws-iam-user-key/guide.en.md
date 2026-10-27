# AWS: access key of an IAM user without rights

An IAM user that has an access key and no permissions at all. You place the key where an intruder looks for credentials: in a credentials file, a deployment configuration or a backup of a home directory. Every request that is signed with the key is recorded by CloudTrail, whether AWS permits it or not, and an EventBridge rule forwards the record to the URL of a honeytoken with a `POST`. The alert says that the key was used. The address and the user agent of the caller are in the start of the request body that the honeytoken keeps, not in the alert: the address of the event itself is that of the AWS service that sends the webhook.

The commands are for a shell such as bash or zsh, with the AWS CLI version 2 and an identity that may create IAM users, roles and EventBridge rules. They were checked against the documentation of the AWS CLI, EventBridge and CloudTrail, not run against an account.

## What the bait does in the account

- The user has no policy, no group, no console password and no permission boundary. The key can sign requests; AWS refuses almost all of them. `sts:GetCallerIdentity` needs no permission, so an intruder learns the user name and the account number. That is the call you want them to make, and it raises the alert like every other call.
- Nothing else in the account changes. The user is not a member of any group, and no role trusts it.
- The secret access key is shown once, when you create the key. It is the bait: it opens nothing.
- Do not use the key yourself, except for the test below, and do not give the user rights later. A user that holds rights is no longer a bait.

## What it needs

1. **A trail that logs management events.** CloudTrail sends events to EventBridge only while a trail is logging, and the trail must log read events as well, because most calls of an intruder only read. Check it in step 1.
2. **A rule in every region where a call can land.** CloudTrail records an event in the region it was made in. The IAM calls and the global endpoint of the security token service are recorded in `us-east-1`; a regional endpoint, which the AWS CLI version 2 uses, is recorded in the region that the intruder configured. You cannot know it. Create the rule in `us-east-1` and in every region that you use, and accept the gap for the others, see Limits.
3. **The URL of the honeytoken**, `https://t.example.net/webhookq3xwz7a2kfm4ub6tyc5nre`. It stands in the API destination in your account. Treat it as a secret: whoever knows it can send forged events, and whoever may read EventBridge resources can find it.

## Step 1: check the trail

```bash
aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,IncludeGlobalServiceEvents,HasCustomEventSelectors]' --output table
aws cloudtrail get-trail-status --name TRAIL_NAME --query IsLogging
```

You need a trail with `IsLogging` true that is multi-region and includes global service events. If `HasCustomEventSelectors` is true, look at them with `aws cloudtrail get-event-selectors --trail-name TRAIL_NAME`: `IncludeManagementEvents` must be true and `ReadWriteType` must be `All`. A trail with advanced event selectors is shown in the console. If you have no trail, create one in the CloudTrail console (Trails, Create trail) and keep management events on, read and write. The console also creates the bucket for the log files. CloudTrail delivers the first copy of the management events at no charge, but the storage in S3 costs.

## Step 2: create the user and the key

```bash
aws iam create-user --user-name svc-reporting-sync
aws iam list-attached-user-policies --user-name svc-reporting-sync
aws iam list-user-policies --user-name svc-reporting-sync
aws iam list-groups-for-user --user-name svc-reporting-sync
aws iam create-access-key --user-name svc-reporting-sync
```

The three `list` commands must return empty lists. If your account adds new users to a group automatically, remove the user from it. The last command prints `AccessKeyId` and `SecretAccessKey`; the secret is not shown again. Keep both for the placement below and clear the output from your terminal.

Choose a name for the user that fits your accounts and says nothing about its purpose.

## Step 3: connection, API destination and role

Set the variables. Use the region of your workloads first; step 5 says when to repeat for another region.

```bash
REGION=eu-central-1
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
```

EventBridge demands a connection with an authorization, which the honeytoken ignores. Any value will do; generate one:

```bash
KEY=$(aws secretsmanager get-random-password --password-length 24 --exclude-punctuation --query RandomPassword --output text)
CONN_ARN=$(aws events create-connection --region "$REGION" --name audit-notify-user-conn --authorization-type API_KEY --auth-parameters "{\"ApiKeyAuthParameters\":{\"ApiKeyName\":\"x-api-key\",\"ApiKeyValue\":\"$KEY\"}}" --query ConnectionArn --output text)
DEST_ARN=$(aws events create-api-destination --region "$REGION" --name audit-notify-user-dest --connection-arn "$CONN_ARN" --invocation-endpoint 'https://t.example.net/webhookq3xwz7a2kfm4ub6tyc5nre' --http-method POST --invocation-rate-limit-per-second 5 --query ApiDestinationArn --output text)
```

EventBridge keeps the key in a secret of Secrets Manager that it manages. The limit of five requests a second keeps a burst of calls from becoming a burst of requests; EventBridge retries what it could not deliver. The role is global, so you create it once:

```bash
aws iam create-role --role-name audit-notify-user-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam put-role-policy --role-name audit-notify-user-role --policy-name invoke --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"events:InvokeApiDestination\",\"Resource\":\"arn:aws:events:*:$ACCOUNT:api-destination/audit-notify-user-dest/*\"}]}"
```

The role may do nothing but invoke this destination, in any region.

## Step 4: the rule

The rule matches every call that the user makes. Read-only calls such as `GetCallerIdentity` reach a rule only in the state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`, which only the AWS CLI and CloudFormation can set.

```bash
cat > pattern.json <<EOF
{"detail-type":["AWS API Call via CloudTrail"],"detail":{"userIdentity":{"type":["IAMUser"],"userName":["svc-reporting-sync"]}}}
EOF
aws events put-rule --region "$REGION" --name audit-notify-user-rule --state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS --event-pattern file://pattern.json
```

The target sends only what you need, so that the request body stays well below the 4096 bytes that the honeytoken keeps. A complete CloudTrail record would not fit.

```bash
cat > targets.json <<EOF
[{"Id":"1","Arn":"$DEST_ARN","RoleArn":"arn:aws:iam::$ACCOUNT:role/audit-notify-user-role","InputTransformer":{"InputPathsMap":{"eventName":"\$.detail.eventName","sourceIPAddress":"\$.detail.sourceIPAddress","userAgent":"\$.detail.userAgent","userArn":"\$.detail.userIdentity.arn","region":"\$.detail.awsRegion","time":"\$.time"},"InputTemplate":"{\"eventName\":<eventName>,\"sourceIPAddress\":<sourceIPAddress>,\"userAgent\":<userAgent>,\"userArn\":<userArn>,\"region\":<region>,\"time\":<time>}"}}]
EOF
aws events put-targets --region "$REGION" --rule audit-notify-user-rule --targets file://targets.json
rm pattern.json targets.json
```

`put-targets` reports `FailedEntryCount`, which must be 0. If it says that the role cannot be assumed, wait a few seconds after creating the role and repeat the command.

## Step 5: more regions

Repeat step 3 without the role, then step 4, for `us-east-1` and for every other region you use: set `REGION` and run the commands again. API destinations exist only in some regions; the documentation of EventBridge lists them.

## Placing the key

Put the key where it is found, in the form the AWS CLI reads. Replace the two values with the output of step 2:

```ini
[default]
aws_access_key_id = ACCESS_KEY_ID
aws_secret_access_key = SECRET_ACCESS_KEY
```

Suitable places are the file `~/.aws/credentials` in a backup of a home directory, a deployment configuration, a repository of scripts or a note with access data. Record where you placed it in the scenario.

## Testing

Configure a profile with the key (the CLI asks for the values, so they stay out of your shell history) and make one call:

```bash
aws configure --profile svc-reporting-sync
aws sts get-caller-identity --profile svc-reporting-sync --region "$REGION"
```

CloudTrail delivers an event within about five minutes of the call on average, which AWS does not guarantee. Then the scenario shows an incident, and the event holds a body like this:

```json
{"eventName":"GetCallerIdentity","sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.x ...","userArn":"arn:aws:iam::123456789012:user/NAME","region":"eu-central-1","time":"2026-01-01T10:00:00Z"}
```

Close the incident after the test, and remove the profile from `~/.aws/credentials` and `~/.aws/config`.

## Removing

```bash
aws events remove-targets --region "$REGION" --rule audit-notify-user-rule --ids 1
aws events delete-rule --region "$REGION" --name audit-notify-user-rule
aws events delete-api-destination --region "$REGION" --name audit-notify-user-dest
aws events delete-connection --region "$REGION" --name audit-notify-user-conn
aws iam delete-role-policy --role-name audit-notify-user-role --policy-name invoke
aws iam delete-role --role-name audit-notify-user-role
aws iam delete-access-key --user-name svc-reporting-sync --access-key-id ACCESS_KEY_ID
aws iam delete-user --user-name svc-reporting-sync
```

Run the first four for every region. Delete the role and the user once.

## Limits

- **Without a trail that logs, nothing arrives.** If someone stops the trail or narrows its selectors, the alert stops without a sign.
- **Regions.** A call to a region without a rule is not reported. An intruder who uses the global endpoint of the security token service lands in `us-east-1`; one who uses a regional endpoint lands where they configured it.
- **Delay.** Minutes, not seconds.
- **Retries.** EventBridge sends a request again when it does not see success in time, so the same call can be reported twice. The honeytoken answers every request alike.
- **The alert names the honeytoken, not the caller.** The address of the event is that of the AWS service that sends the webhook. The caller, its address and its user agent are only in the start of the body, which the console shows as text of an attacker and which appears in no alert.
- **Only requests that arrive at your account are recorded.** What an intruder can learn about the key without sending a request to your account leaves no trace there.
- **Visible to those who look.** An intruder with read access to IAM sees a user without rights, and one with read access to EventBridge sees the destination with its URL.
