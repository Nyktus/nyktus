# AWS: sicherer Parameter im Parameter Store

Ein Parameter vom Typ `SecureString` im AWS Systems Manager Parameter Store, der einen zufälligen Wert enthält. Ein Eindringling, der eine Identität Ihres Kontos übernommen hat, sucht nach Parametern mit einem Namen wie `prod-orders-api-key` und liest ihn mit Entschlüsselung. CloudTrail zeichnet das Lesen auf, und eine EventBridge-Regel leitet den Eintrag per `POST` an die URL eines Honeytokens weiter. Der Alert sagt, dass der Parameter gelesen wurde. Identität und Adresse des Aufrufers stehen im Anfang des Request-Body, den der Honeytoken aufbewahrt, nicht im Alert: Die Adresse des Events selbst ist die des AWS-Dienstes, der den Webhook sendet.

Die Befehle sind für eine Shell wie bash oder zsh gedacht, mit der AWS CLI in Version 2 und einer Identität, die Parameter, IAM-Rollen und EventBridge-Regeln anlegen darf. Sie wurden an der Dokumentation der AWS CLI, von EventBridge, CloudTrail und Systems Manager geprüft, nicht an einem Konto ausgeführt.

## Was der Köder im Konto bewirkt

- Der Parameter enthält einen zufälligen Wert mit 24 Zeichen von AWS. Er gehört zu nichts: Das Lesen öffnet nichts. Er liegt in der Standardstufe, für die Systems Manager keine zusätzliche Gebühr erhebt, und benutzt den Standardschlüssel für `SecureString`.
- Keine andere Ressource ändert sich, und am Parameter hängt keine Richtlinie.
- Der Wert steht beim Anlegen des Parameters auf der Befehlszeile und ist damit für einen Augenblick für andere Benutzer desselben Rechners sichtbar. Für einen Wert, der nichts öffnet, ist das hinnehmbar.
- Alles in Ihrem Konto, das alle Parameter liest, etwa ein Inventarwerkzeug oder ein Scanner, liest auch diesen und löst den Alert aus. Suchen Sie diese zuerst und nehmen Sie ihre Identitäten mit einem `anything-but`-Filter auf `userIdentity.arn` aus dem Muster in Schritt 3 heraus.

## Was dazu nötig ist

1. **Ein Trail, der Management-Ereignisse aufzeichnet**, auch lesende. CloudTrail schickt Ereignisse nur an EventBridge, solange ein Trail aufzeichnet, und das Lesen eines Parameters ist ein lesendes Ereignis. Prüfen Sie ihn wie in Schritt 1.
2. **Eine Regel in der Region des Parameters.** Ein Parameter gehört zu einer Region, und CloudTrail zeichnet einen Aufruf in dieser Region auf.
3. **Die URL des Honeytokens**, `https://t.example.net/webhookq3xwz7a2kfm4ub6tyc5nre`. Sie steht im API-Ziel in Ihrem Konto. Behandeln Sie sie als Geheimnis: Wer sie kennt, kann gefälschte Events senden, und wer EventBridge-Ressourcen lesen darf, kann sie finden.
4. **Ein Name ohne Schrägstriche.** Der Name des Parameters darf Buchstaben, Ziffern, Punkte, Bindestriche und Unterstriche enthalten und nicht mit `aws` oder `ssm` beginnen. Ein flacher Name ist im Parameter Store gültig.

## Schritt 1: Trail prüfen

```bash
aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,HasCustomEventSelectors]' --output table
aws cloudtrail get-trail-status --name TRAIL_NAME --query IsLogging
```

Sie brauchen einen Trail mit `IsLogging` wahr, der die Region des Parameters umfasst. Ist `HasCustomEventSelectors` wahr, sehen Sie sie mit `aws cloudtrail get-event-selectors --trail-name TRAIL_NAME` an: `IncludeManagementEvents` muss wahr und `ReadWriteType` muss `All` sein. Einen Trail mit erweiterten Ereignisauswahlen zeigt die Konsole. Haben Sie keinen Trail, legen Sie in der CloudTrail-Konsole einen an (Trails, Create trail) und lassen Sie Management-Ereignisse eingeschaltet, lesend und schreibend. Die Konsole legt auch den Bucket für die Logdateien an. CloudTrail liefert die erste Kopie der Management-Ereignisse ohne Gebühr, der Speicher in S3 kostet aber.

## Schritt 2: Parameter anlegen

```bash
REGION=eu-central-1
aws ssm put-parameter --region "$REGION" --name prod-orders-api-key --type SecureString --tier Standard --value "$(aws secretsmanager get-random-password --region "$REGION" --password-length 24 --exclude-punctuation --query RandomPassword --output text)"
```

Wählen Sie einen Namen, der dazu passt, wie Ihre Teams Parameter benennen.

## Schritt 3: Verbindung, API-Ziel, Rolle und Regel

```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
KEY=$(aws secretsmanager get-random-password --region "$REGION" --password-length 24 --exclude-punctuation --query RandomPassword --output text)
CONN_ARN=$(aws events create-connection --region "$REGION" --name audit-notify-param-conn --authorization-type API_KEY --auth-parameters "{\"ApiKeyAuthParameters\":{\"ApiKeyName\":\"x-api-key\",\"ApiKeyValue\":\"$KEY\"}}" --query ConnectionArn --output text)
DEST_ARN=$(aws events create-api-destination --region "$REGION" --name audit-notify-param-dest --connection-arn "$CONN_ARN" --invocation-endpoint 'https://t.example.net/webhookq3xwz7a2kfm4ub6tyc5nre' --http-method POST --invocation-rate-limit-per-second 5 --query ApiDestinationArn --output text)
```

EventBridge verlangt eine Verbindung mit einer Autorisierung, die der Honeytoken ignoriert, und legt den Schlüssel in einem Secret von Secrets Manager ab, das es selbst verwaltet. Die Grenze von fünf Anfragen pro Sekunde verhindert, dass ein Schwall von Aufrufen zu einem Schwall von Anfragen wird; was EventBridge nicht zustellen konnte, versucht es erneut.

Die Rolle darf nichts außer diesem Ziel aufrufen:

```bash
aws iam create-role --role-name audit-notify-param-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam put-role-policy --role-name audit-notify-param-role --policy-name invoke --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"events:InvokeApiDestination\",\"Resource\":\"arn:aws:events:*:$ACCOUNT:api-destination/audit-notify-param-dest/*\"}]}"
```

Die Regel erfasst das Lesen des Parameters mit `GetParameter` und `GetParameters`, mit oder ohne führenden Schrägstrich. Das Lesen ist ein lesender Aufruf, und lesende Aufrufe erreichen eine Regel nur im Zustand `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`, den nur die AWS CLI und CloudFormation setzen können.

```bash
cat > pattern.json <<EOF
{"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["ssm.amazonaws.com"],"\$or":[{"eventName":["GetParameter"],"requestParameters":{"name":["prod-orders-api-key","/prod-orders-api-key"]}},{"eventName":["GetParameters"],"requestParameters":{"names":["prod-orders-api-key","/prod-orders-api-key"]}}]}}
EOF
aws events put-rule --region "$REGION" --name audit-notify-param-rule --state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS --event-pattern file://pattern.json
```

Das Ziel sendet nur, was Sie brauchen, damit der Request-Body weit unter den 4096 Byte bleibt, die der Honeytoken aufbewahrt. Ein vollständiger CloudTrail-Eintrag passt nicht hinein.

```bash
cat > targets.json <<EOF
[{"Id":"1","Arn":"$DEST_ARN","RoleArn":"arn:aws:iam::$ACCOUNT:role/audit-notify-param-role","InputTransformer":{"InputPathsMap":{"eventName":"\$.detail.eventName","sourceIPAddress":"\$.detail.sourceIPAddress","userAgent":"\$.detail.userAgent","userArn":"\$.detail.userIdentity.arn","region":"\$.detail.awsRegion","time":"\$.time"},"InputTemplate":"{\"eventName\":<eventName>,\"sourceIPAddress\":<sourceIPAddress>,\"userAgent\":<userAgent>,\"userArn\":<userArn>,\"region\":<region>,\"time\":<time>}"}}]
EOF
aws events put-targets --region "$REGION" --rule audit-notify-param-rule --targets file://targets.json
rm pattern.json targets.json
```

`put-targets` meldet `FailedEntryCount`, der 0 sein muss. Heißt es, die Rolle könne nicht übernommen werden, warten Sie nach dem Anlegen der Rolle einige Sekunden und wiederholen Sie den Befehl.

## Den Köder platzieren

Den Parameter findet man, indem man die Parameter des Kontos auflistet, er braucht also keine Datei. Damit er früher gefunden wird, nennen Sie seinen Namen dort, wo es die Menschen der Geschichte täten: in der Readme eines Repositorys, in einer Deployment-Konfiguration (`prod-orders-api-key` als Name des zu ladenden Parameters) oder in einem Ticket. Vermerken Sie im Szenario, wo Sie das getan haben.

## Testen

Lesen Sie den Parameter mit Ihrer eigenen Identität:

```bash
aws ssm get-parameter --region "$REGION" --name prod-orders-api-key --query Parameter.Name --output text
```

CloudTrail liefert ein Ereignis im Durchschnitt etwa fünf Minuten nach dem Aufruf, garantiert ist das von AWS nicht. Dann zeigt das Szenario einen Incident, und das Event enthält einen Body wie diesen:

```json
{"eventName":"GetParameter","sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.x ...","userArn":"arn:aws:sts::123456789012:assumed-role/NAME/SESSION","region":"eu-central-1","time":"2026-01-01T10:00:00Z"}
```

Schließen Sie den Incident nach dem Test.

## Entfernen

```bash
aws events remove-targets --region "$REGION" --rule audit-notify-param-rule --ids 1
aws events delete-rule --region "$REGION" --name audit-notify-param-rule
aws events delete-api-destination --region "$REGION" --name audit-notify-param-dest
aws events delete-connection --region "$REGION" --name audit-notify-param-conn
aws iam delete-role-policy --role-name audit-notify-param-role --policy-name invoke
aws iam delete-role --role-name audit-notify-param-role
aws ssm delete-parameter --region "$REGION" --name prod-orders-api-key
```

## Grenzen

- **Ohne aufzeichnenden Trail kommt nichts an.** Hält jemand den Trail an oder engt seine Auswahl ein, endet der Alert ohne Anzeichen.
- **Eine Region.** Gemeldet werden nur Aufrufe an die Region des Parameters, also dorthin, wo der Parameter liegt.
- **Was erfasst wird.** `GetParameter` und `GetParameters` über den Namen. `GetParametersByPath` nennt einen Pfad, nicht den Parameter, und `GetParameterHistory` und `DescribeParameters` werden nicht erfasst; ein Eindringling, der ganze Pfade liest, wird also nicht gemeldet.
- **Verzögerung.** Minuten, nicht Sekunden.
- **Wiederholungen.** EventBridge sendet eine Anfrage erneut, wenn es nicht rechtzeitig Erfolg sieht, derselbe Aufruf kann also zweimal gemeldet werden. Der Honeytoken beantwortet jede Anfrage gleich.
- **Der Alert nennt den Honeytoken, nicht den Aufrufer.** Die Adresse des Events ist die des AWS-Dienstes, der den Webhook sendet. Aufrufer, Adresse und User-Agent stehen nur im Anfang des Body, den die Console als Text eines Angreifers zeigt und der in keinem Alert steht.
- **Ihre eigenen Werkzeuge.** Alles von Ihnen, das den Parameter liest, auch Sie selbst, löst den Alert aus.
- **Sichtbar für jeden, der nachsieht.** Ein Eindringling mit Leserechten in EventBridge sieht das Ziel samt URL.
