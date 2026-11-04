# AWS: secret in Secrets Manager

A secret in AWS Secrets Manager that holds a user name and a password for a database that does not exist. An intruder who has taken over an identity of your account lists the secrets, finds one with a name like `prod-orders-db-credentials` and reads it. CloudTrail records the read, and an EventBridge rule forwards the record to the URL of a honeytoken with a `POST`. The alert says that the secret was read or described. The identity and the address of the caller are in the start of the request body that the honeytoken keeps, not in the alert: the address of the event itself is that of the AWS service that sends the webhook.

The commands are for a shell such as bash or zsh, with the AWS CLI version 2 and an identity that may create secrets, IAM roles and EventBridge rules. They were checked against the documentation of the AWS CLI, EventBridge and CloudTrail, not run against an account.

## What the bait does in the account

- The secret holds the user name `orders_app` and a random password of 24 characters from AWS. Both are invented: no account of that name exists anywhere, and nobody keeps the password. Reading the secret opens nothing.
- No other resource is changed, and no policy is attached to the secret. The secret uses the default key of Secrets Manager.
- Secrets Manager charges a monthly fee for each secret and for its use; see the pricing page. Nothing else here costs more than a few requests.
- Everything in your account that reads all secrets, such as an inventory tool, a security scanner or a backup, also reads this one and raises the alert. Find those first, and exclude their identities from the pattern in step 3 with an `anything-but` filter on `userIdentity.arn`.

## What it needs

1. **A trail that logs management events**, including read events. CloudTrail sends events to EventBridge only while a trail is logging, and reading a secret is a read event. Check it as in step 1.
2. **A rule in the region of the secret.** A secret belongs to a region, and CloudTrail records a call in the region of the secret. One rule in that region is enough.
3. **The URL of the honeytoken**, `Honeytoken-URL`. It stands in the API destination in your account. Treat it as a secret: whoever knows it can send forged events, and whoever may read EventBridge resources can find it.

## Step 1: check the trail

```bash
aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,HasCustomEventSelectors]' --output table
aws cloudtrail get-trail-status --name TRAIL_NAME --query IsLogging
```

You need a trail with `IsLogging` true that covers the region of the secret. If `HasCustomEventSelectors` is true, look at them with `aws cloudtrail get-event-selectors --trail-name TRAIL_NAME`: `IncludeManagementEvents` must be true and `ReadWriteType` must be `All`. A trail with advanced event selectors is shown in the console. If you have no trail, create one in the CloudTrail console (Trails, Create trail) and keep management events on, read and write. The console also creates the bucket for the log files. CloudTrail delivers the first copy of the management events at no charge, but the storage in S3 costs.

## Step 2: create the secret

The password comes from AWS and passes through a shell variable, so that it is not printed. It stands on the command line of `create-secret` for a moment, where other users of the same computer can see it. That is acceptable for a value that opens nothing:

```bash
REGION=eu-central-1
SECRET_JSON=$(aws secretsmanager get-random-password --region "$REGION" --password-length 24 --exclude-punctuation --query "{username: 'orders_app', password: RandomPassword}" --output json)
aws secretsmanager create-secret --region "$REGION" --name prod-orders-db-credentials --secret-string "$SECRET_JSON" --query ARN --output text
unset SECRET_JSON
```

Choose a name for the secret that fits the way your teams name secrets, and make sure that no other secret has a name that begins with it: the rule below matches by that name.

## Step 3: connection, API destination, role and rule

```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
KEY=$(aws secretsmanager get-random-password --region "$REGION" --password-length 24 --exclude-punctuation --query RandomPassword --output text)
CONN_ARN=$(aws events create-connection --region "$REGION" --name audit-notify-secret-conn --authorization-type API_KEY --auth-parameters "{\"ApiKeyAuthParameters\":{\"ApiKeyName\":\"x-api-key\",\"ApiKeyValue\":\"$KEY\"}}" --query ConnectionArn --output text)
DEST_ARN=$(aws events create-api-destination --region "$REGION" --name audit-notify-secret-dest --connection-arn "$CONN_ARN" --invocation-endpoint 'Honeytoken-URL' --http-method POST --invocation-rate-limit-per-second 5 --query ApiDestinationArn --output text)
```

EventBridge demands a connection with an authorization, which the honeytoken ignores, and keeps the key in a secret of Secrets Manager that it manages. The limit of five requests a second keeps a burst of calls from becoming a burst of requests; EventBridge retries what it could not deliver.

The role may do nothing but invoke this destination:

```bash
aws iam create-role --role-name audit-notify-secret-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam put-role-policy --role-name audit-notify-secret-role --policy-name invoke --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"events:InvokeApiDestination\",\"Resource\":\"arn:aws:events:*:$ACCOUNT:api-destination/audit-notify-secret-dest/*\"}]}"
```

The rule matches reading and describing the secret, by its name or by its ARN. Reading is a read-only call, and read-only calls reach a rule only in the state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`, which only the AWS CLI and CloudFormation can set. Listing secrets does not name this one and is not matched.

```bash
cat > pattern.json <<EOF
{"source":["aws.secretsmanager"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["secretsmanager.amazonaws.com"],"eventName":["GetSecretValue","DescribeSecret"],"requestParameters":{"secretId":["prod-orders-db-credentials",{"prefix":"arn:aws:secretsmanager:$REGION:$ACCOUNT:secret:prod-orders-db-credentials-"}]}}}
EOF
aws events put-rule --region "$REGION" --name audit-notify-secret-rule --state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS --event-pattern file://pattern.json
```

The target sends only what you need, so that the request body stays well below the 4096 bytes that the honeytoken keeps. A complete CloudTrail record would not fit.

```bash
cat > targets.json <<EOF
[{"Id":"1","Arn":"$DEST_ARN","RoleArn":"arn:aws:iam::$ACCOUNT:role/audit-notify-secret-role","InputTransformer":{"InputPathsMap":{"eventName":"\$.detail.eventName","sourceIPAddress":"\$.detail.sourceIPAddress","userAgent":"\$.detail.userAgent","userArn":"\$.detail.userIdentity.arn","userType":"\$.detail.userIdentity.type","accountId":"\$.detail.userIdentity.accountId","region":"\$.detail.awsRegion","time":"\$.time"},"InputTemplate":"{\"eventName\":<eventName>,\"sourceIPAddress\":<sourceIPAddress>,\"userAgent\":<userAgent>,\"userArn\":<userArn>,\"userType\":<userType>,\"accountId\":<accountId>,\"region\":<region>,\"time\":<time>}"}}]
EOF
aws events put-targets --region "$REGION" --rule audit-notify-secret-rule --targets file://targets.json
rm pattern.json targets.json
```

`put-targets` reports `FailedEntryCount`, which must be 0. If it says that the role cannot be assumed, wait a few seconds after creating the role and repeat the command.

## Placing the bait

The secret is found by listing the secrets of the account, so it needs no file. To make it found sooner, mention its name where the people of the story would: in the readme of a repository, in a deployment configuration (`prod-orders-db-credentials` as the name of the secret to load) or in a ticket. Record where you did it in the scenario.

## Testing

With your own identity, read the secret:

```bash
aws secretsmanager get-secret-value --region "$REGION" --secret-id prod-orders-db-credentials --query Name --output text
```

CloudTrail delivers an event within about five minutes of the call on average, which AWS does not guarantee. Then the scenario shows an incident, and the event holds a body like this:

```json
{"eventName":"GetSecretValue","sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.x ...","userArn":"arn:aws:sts::123456789012:assumed-role/NAME/SESSION","userType":"AssumedRole","accountId":"123456789012","region":"eu-central-1","time":"2026-01-01T10:00:00Z"}
```

Close the incident after the test.

## Removing

```bash
aws events remove-targets --region "$REGION" --rule audit-notify-secret-rule --ids 1
aws events delete-rule --region "$REGION" --name audit-notify-secret-rule
aws events delete-api-destination --region "$REGION" --name audit-notify-secret-dest
aws events delete-connection --region "$REGION" --name audit-notify-secret-conn
aws iam delete-role-policy --role-name audit-notify-secret-role --policy-name invoke
aws iam delete-role --role-name audit-notify-secret-role
aws secretsmanager delete-secret --region "$REGION" --secret-id prod-orders-db-credentials --force-delete-without-recovery
```

## Limits

- **Without a trail that logs, nothing arrives.** If someone stops the trail or narrows its selectors, the alert stops without a sign.
- **One region.** Only calls to the region of the secret are reported, which is where the secret lives.
- **What is matched.** Reading and describing by name or ARN. `BatchGetSecretValue` names the secrets in a list that the pattern does not look at, so an intruder who reads secrets in a batch is not reported. Listing the secrets raises nothing.
- **Delay.** Minutes, not seconds.
- **Retries.** EventBridge sends a request again when it does not see success in time, so the same call can be reported twice. The honeytoken answers every request alike.
- **The alert names the honeytoken, not the caller.** The address of the event is that of the AWS service that sends the webhook. The caller, its address and its user agent are only in the start of the body, which the console shows as text of an attacker and which appears in no alert.
- **Your own tools.** Anything of yours that reads the secret, including you, raises the alert.
- **Visible to those who look.** An intruder with read access to EventBridge sees the destination with its URL.
