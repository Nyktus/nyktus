# AWS: IAM-Rolle, die nichts gewährt

Eine IAM-Rolle mit einem Namen, den ein Eindringling benutzen möchte, etwa `deploy-admin`, die den Prinzipalen Ihres eigenen Kontos vertraut und gar keine Berechtigungen hat. Ein Eindringling, der eine Identität übernommen hat, listet die Rollen auf und versucht, die anzunehmen, die mächtig klingt. CloudTrail zeichnet den Versuch auf, gleich ob AWS ihn erlaubt, und eine EventBridge-Regel leitet den Eintrag per `POST` an die URL eines Honeytokens weiter. Der Alert sagt, dass die Rolle angenommen wurde oder dass es jemand versucht hat. Identität und Adresse des Aufrufers stehen im Anfang des Request-Body, den der Honeytoken aufbewahrt, nicht im Alert: Die Adresse des Events selbst ist die des AWS-Dienstes, der den Webhook sendet.

Die Befehle sind für eine Shell wie bash oder zsh gedacht, mit der AWS CLI in Version 2 und einer Identität, die IAM-Rollen und EventBridge-Regeln anlegen darf. Sie wurden an der Dokumentation der AWS CLI, von EventBridge und von CloudTrail geprüft, nicht an einem Konto ausgeführt.

## Was der Köder im Konto bewirkt

- Die Rolle vertraut dem Root Ihres Kontos. Jede Identität des Kontos, die `sts:AssumeRole` für sie aufrufen darf, kann sie also annehmen. Die Rolle selbst hat keine Richtlinie, keine Berechtigungsgrenze und keine Inline-Richtlinie, eine Sitzung der Rolle kann also nichts tun.
- Im Konto ändert sich sonst nichts.
- Hängen Sie der Rolle später keine Richtlinie an. Eine Rolle mit Berechtigungen ist kein Köder mehr.
- Identitäten mit weitreichenden Rechten, etwa Administratoren und Automatisierung, können die Rolle annehmen. Nimmt eines Ihrer eigenen Werkzeuge jede Rolle an, die es findet, löst es den Alert aus.

## Was dazu nötig ist

1. **Ein Trail, der Management-Ereignisse aufzeichnet**, auch lesende. CloudTrail schickt Ereignisse nur an EventBridge, solange ein Trail aufzeichnet. Prüfen Sie ihn wie in Schritt 1.
2. **Eine Regel in jeder Region, in der ein Aufruf landen kann.** CloudTrail zeichnet ein Ereignis in der Region auf, in der es stattfand. Ein Aufruf des globalen Endpunkts des Security Token Service wird in `us-east-1` aufgezeichnet, der eines regionalen Endpunkts, den die AWS CLI in Version 2 benutzt, in der Region, die der Eindringling eingestellt hat. Legen Sie die Regel in `us-east-1` und in jeder Region an, die Sie benutzen, und nehmen Sie die Lücke für die übrigen in Kauf, siehe Grenzen.
3. **Die URL des Honeytokens**, `https://t.example.net/webhookq3xwz7a2kfm4ub6tyc5nre`. Sie steht im API-Ziel in Ihrem Konto. Behandeln Sie sie als Geheimnis: Wer sie kennt, kann gefälschte Events senden, und wer EventBridge-Ressourcen lesen darf, kann sie finden.

## Schritt 1: Trail prüfen

```bash
aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,IncludeGlobalServiceEvents,HasCustomEventSelectors]' --output table
aws cloudtrail get-trail-status --name TRAIL_NAME --query IsLogging
```

Sie brauchen einen Trail mit `IsLogging` wahr, der mehrere Regionen umfasst und globale Dienstereignisse einschließt. Ist `HasCustomEventSelectors` wahr, sehen Sie sie mit `aws cloudtrail get-event-selectors --trail-name TRAIL_NAME` an: `IncludeManagementEvents` muss wahr und `ReadWriteType` muss `All` sein. Einen Trail mit erweiterten Ereignisauswahlen zeigt die Konsole. Haben Sie keinen Trail, legen Sie in der CloudTrail-Konsole einen an (Trails, Create trail) und lassen Sie Management-Ereignisse eingeschaltet, lesend und schreibend. Die Konsole legt auch den Bucket für die Logdateien an. CloudTrail liefert die erste Kopie der Management-Ereignisse ohne Gebühr, der Speicher in S3 kostet aber.

## Schritt 2: Rolle anlegen

```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
aws iam create-role --role-name deploy-admin --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::$ACCOUNT:root\"},\"Action\":\"sts:AssumeRole\"}]}"
aws iam list-attached-role-policies --role-name deploy-admin
aws iam list-role-policies --role-name deploy-admin
```

Die beiden `list`-Befehle müssen leere Listen liefern. Wählen Sie einen Namen, der zu Ihren Rollen passt und den ein Eindringling haben will: Namen für Deployment, Sicherung und Administration eignen sich gut.

## Schritt 3: Verbindung, API-Ziel und Rolle für die Regel

Setzen Sie die Region. Nehmen Sie zuerst die Region Ihrer Workloads; Schritt 5 sagt, wann Sie für eine andere Region wiederholen.

```bash
REGION=eu-central-1
KEY=$(aws secretsmanager get-random-password --region "$REGION" --password-length 24 --exclude-punctuation --query RandomPassword --output text)
CONN_ARN=$(aws events create-connection --region "$REGION" --name audit-notify-role-conn --authorization-type API_KEY --auth-parameters "{\"ApiKeyAuthParameters\":{\"ApiKeyName\":\"x-api-key\",\"ApiKeyValue\":\"$KEY\"}}" --query ConnectionArn --output text)
DEST_ARN=$(aws events create-api-destination --region "$REGION" --name audit-notify-role-dest --connection-arn "$CONN_ARN" --invocation-endpoint 'https://t.example.net/webhookq3xwz7a2kfm4ub6tyc5nre' --http-method POST --invocation-rate-limit-per-second 5 --query ApiDestinationArn --output text)
```

EventBridge verlangt eine Verbindung mit einer Autorisierung, die der Honeytoken ignoriert, und legt den Schlüssel in einem Secret von Secrets Manager ab, das es selbst verwaltet. Die Grenze von fünf Anfragen pro Sekunde verhindert, dass ein Schwall von Aufrufen zu einem Schwall von Anfragen wird; was EventBridge nicht zustellen konnte, versucht es erneut. Die Rolle für die Regel ist global, Sie legen sie also einmal an. Sie darf nichts außer diesem Ziel aufrufen, in jeder Region:

```bash
aws iam create-role --role-name audit-notify-role-invoke --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam put-role-policy --role-name audit-notify-role-invoke --policy-name invoke --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"events:InvokeApiDestination\",\"Resource\":\"arn:aws:events:*:$ACCOUNT:api-destination/audit-notify-role-dest/*\"}]}"
```

## Schritt 4: die Regel

Die Regel erfasst jeden Versuch, die Rolle anzunehmen, über ihre ARN. EventBridge zählt `AssumeRole` zu den lesenden Management-Ereignissen, und diese erreichen eine Regel nur im Zustand `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`, den nur die AWS CLI und CloudFormation setzen können.

```bash
cat > pattern.json <<EOF
{"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["sts.amazonaws.com"],"eventName":["AssumeRole"],"requestParameters":{"roleArn":["arn:aws:iam::$ACCOUNT:role/deploy-admin"]}}}
EOF
aws events put-rule --region "$REGION" --name audit-notify-role-rule --state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS --event-pattern file://pattern.json
```

Das Ziel sendet nur, was Sie brauchen, damit der Request-Body weit unter den 4096 Byte bleibt, die der Honeytoken aufbewahrt. Ein vollständiger CloudTrail-Eintrag passt nicht hinein.

```bash
cat > targets.json <<EOF
[{"Id":"1","Arn":"$DEST_ARN","RoleArn":"arn:aws:iam::$ACCOUNT:role/audit-notify-role-invoke","InputTransformer":{"InputPathsMap":{"eventName":"\$.detail.eventName","sourceIPAddress":"\$.detail.sourceIPAddress","userAgent":"\$.detail.userAgent","userArn":"\$.detail.userIdentity.arn","region":"\$.detail.awsRegion","time":"\$.time"},"InputTemplate":"{\"eventName\":<eventName>,\"sourceIPAddress\":<sourceIPAddress>,\"userAgent\":<userAgent>,\"userArn\":<userArn>,\"region\":<region>,\"time\":<time>}"}}]
EOF
aws events put-targets --region "$REGION" --rule audit-notify-role-rule --targets file://targets.json
rm pattern.json targets.json
```

`put-targets` meldet `FailedEntryCount`, der 0 sein muss. Heißt es, die Rolle könne nicht übernommen werden, warten Sie nach dem Anlegen der Rolle einige Sekunden und wiederholen Sie den Befehl.

## Schritt 5: weitere Regionen

Wiederholen Sie Schritt 3 ohne die Rolle für die Regel und dann Schritt 4 für `us-east-1` und für jede weitere Region, die Sie benutzen: Setzen Sie `REGION` und führen Sie die Befehle erneut aus. API-Ziele gibt es nur in manchen Regionen; die Dokumentation von EventBridge listet sie auf.

## Den Köder platzieren

Die Rolle findet man, indem man die Rollen des Kontos auflistet, sie braucht also keine Datei. Damit sie früher gefunden wird, nennen Sie ihren Namen dort, wo es die Menschen der Geschichte täten: in einem Deployment-Skript (`aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/deploy-admin`), einem Profil der AWS CLI mit `role_arn` oder einem Ticket. Vermerken Sie im Szenario, wo Sie das getan haben.

## Testen

Versuchen Sie mit Ihrer eigenen Identität, die Rolle anzunehmen. Ob Ihre Identität es darf oder nicht, beides wird aufgezeichnet:

```bash
aws sts assume-role --region "$REGION" --role-arn arn:aws:iam::$ACCOUNT:role/deploy-admin --role-session-name test --query AssumedRoleUser.Arn --output text
```

CloudTrail liefert ein Ereignis im Durchschnitt etwa fünf Minuten nach dem Aufruf, garantiert ist das von AWS nicht. Dann zeigt das Szenario einen Incident, und das Event enthält einen Body wie diesen:

```json
{"eventName":"AssumeRole","sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.x ...","userArn":"arn:aws:sts::123456789012:assumed-role/NAME/SESSION","region":"eu-central-1","time":"2026-01-01T10:00:00Z"}
```

Schließen Sie den Incident nach dem Test.

## Entfernen

```bash
aws events remove-targets --region "$REGION" --rule audit-notify-role-rule --ids 1
aws events delete-rule --region "$REGION" --name audit-notify-role-rule
aws events delete-api-destination --region "$REGION" --name audit-notify-role-dest
aws events delete-connection --region "$REGION" --name audit-notify-role-conn
aws iam delete-role-policy --role-name audit-notify-role-invoke --policy-name invoke
aws iam delete-role --role-name audit-notify-role-invoke
aws iam delete-role --role-name deploy-admin
```

Die ersten vier führen Sie für jede Region aus. Die Rollen löschen Sie einmal.

## Grenzen

- **Ohne aufzeichnenden Trail kommt nichts an.** Hält jemand den Trail an oder engt seine Auswahl ein, endet der Alert ohne Anzeichen.
- **Regionen.** Ein Versuch, der in einer Region ohne Regel landet, wird nicht gemeldet. Ein Eindringling, der den globalen Endpunkt des Security Token Service benutzt, landet in `us-east-1`; wer einen regionalen Endpunkt benutzt, dort, wo er ihn eingestellt hat.
- **Nur der Versuch, nicht die Nutzung.** Die Rolle anzunehmen bringt dem Eindringling nichts, es gibt also nichts weiter zu sehen.
- **Verzögerung.** Minuten, nicht Sekunden.
- **Wiederholungen.** EventBridge sendet eine Anfrage erneut, wenn es nicht rechtzeitig Erfolg sieht, derselbe Aufruf kann also zweimal gemeldet werden. Der Honeytoken beantwortet jede Anfrage gleich.
- **Der Alert nennt den Honeytoken, nicht den Aufrufer.** Die Adresse des Events ist die des AWS-Dienstes, der den Webhook sendet. Aufrufer, Adresse und User-Agent stehen nur im Anfang des Body, den die Console als Text eines Angreifers zeigt und der in keinem Alert steht.
- **Ihre eigenen Werkzeuge.** Alles von Ihnen, das versucht, die Rolle anzunehmen, auch Sie selbst, löst den Alert aus.
- **Sichtbar für jeden, der nachsieht.** Ein Eindringling mit Leserechten in IAM sieht eine Rolle ohne Berechtigungen, einer mit Leserechten in EventBridge das Ziel samt URL.
