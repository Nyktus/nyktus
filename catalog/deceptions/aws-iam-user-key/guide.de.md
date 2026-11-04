# AWS: Zugriffsschlüssel eines IAM-Benutzers ohne Rechte

Ein IAM-Benutzer, der einen Zugriffsschlüssel und gar keine Berechtigungen hat. Sie legen den Schlüssel dort ab, wo ein Eindringling nach Zugangsdaten sucht: in einer Credentials-Datei, einer Deployment-Konfiguration oder einer Sicherung eines Home-Verzeichnisses. Jede Anfrage, die mit dem Schlüssel signiert wird, zeichnet CloudTrail auf, gleich ob AWS sie erlaubt, und eine EventBridge-Regel leitet den Eintrag per `POST` an die URL eines Honeytokens weiter. Der Alert sagt, dass der Schlüssel benutzt wurde. Adresse und User-Agent des Aufrufers stehen im Anfang des Request-Body, den der Honeytoken aufbewahrt, nicht im Alert: Die Adresse des Events selbst ist die des AWS-Dienstes, der den Webhook sendet.

Die Befehle sind für eine Shell wie bash oder zsh gedacht, mit der AWS CLI in Version 2 und einer Identität, die IAM-Benutzer, Rollen und EventBridge-Regeln anlegen darf. Sie wurden an der Dokumentation der AWS CLI, von EventBridge und von CloudTrail geprüft, nicht an einem Konto ausgeführt.

## Was der Köder im Konto bewirkt

- Der Benutzer hat keine Richtlinie, keine Gruppe, kein Konsolenpasswort und keine Berechtigungsgrenze. Der Schlüssel kann Anfragen signieren; AWS lehnt fast alle ab. `sts:GetCallerIdentity` braucht keine Berechtigung, ein Eindringling erfährt also Benutzername und Kontonummer. Das ist der Aufruf, den Sie erwarten, und er löst den Alert aus wie jeder andere.
- Im Konto ändert sich sonst nichts. Der Benutzer ist in keiner Gruppe, und keine Rolle vertraut ihm.
- Der geheime Zugriffsschlüssel wird einmal angezeigt, beim Anlegen des Schlüssels. Er ist der Köder: Er öffnet nichts.
- Benutzen Sie den Schlüssel nicht selbst, außer für den Test unten, und geben Sie dem Benutzer später keine Rechte. Ein Benutzer mit Rechten ist kein Köder mehr.

## Was dazu nötig ist

1. **Ein Trail, der Management-Ereignisse aufzeichnet.** CloudTrail schickt Ereignisse nur an EventBridge, solange ein Trail aufzeichnet, und der Trail muss auch lesende Ereignisse aufzeichnen, weil die meisten Aufrufe eines Eindringlings nur lesen. Prüfen Sie das in Schritt 1.
2. **Eine Regel in jeder Region, in der ein Aufruf landen kann.** CloudTrail zeichnet ein Ereignis in der Region auf, in der es stattfand. Die IAM-Aufrufe und der globale Endpunkt des Security Token Service werden in `us-east-1` aufgezeichnet; ein regionaler Endpunkt, den die AWS CLI in Version 2 benutzt, in der Region, die der Eindringling eingestellt hat. Sie können sie nicht kennen. Legen Sie die Regel in `us-east-1` und in jeder Region an, die Sie benutzen, und nehmen Sie die Lücke für die übrigen in Kauf, siehe Grenzen.
3. **Die URL des Honeytokens**, `Honeytoken-URL`. Sie steht im API-Ziel in Ihrem Konto. Behandeln Sie sie als Geheimnis: Wer sie kennt, kann gefälschte Events senden, und wer EventBridge-Ressourcen lesen darf, kann sie finden.

## Schritt 1: Trail prüfen

```bash
aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,IncludeGlobalServiceEvents,HasCustomEventSelectors]' --output table
aws cloudtrail get-trail-status --name TRAIL_NAME --query IsLogging
```

Sie brauchen einen Trail mit `IsLogging` wahr, der mehrere Regionen umfasst und globale Dienstereignisse einschließt. Ist `HasCustomEventSelectors` wahr, sehen Sie sie mit `aws cloudtrail get-event-selectors --trail-name TRAIL_NAME` an: `IncludeManagementEvents` muss wahr und `ReadWriteType` muss `All` sein. Einen Trail mit erweiterten Ereignisauswahlen zeigt die Konsole. Haben Sie keinen Trail, legen Sie in der CloudTrail-Konsole einen an (Trails, Create trail) und lassen Sie Management-Ereignisse eingeschaltet, lesend und schreibend. Die Konsole legt auch den Bucket für die Logdateien an. CloudTrail liefert die erste Kopie der Management-Ereignisse ohne Gebühr, der Speicher in S3 kostet aber.

## Schritt 2: Benutzer und Schlüssel anlegen

```bash
aws iam create-user --user-name svc-reporting-sync
aws iam list-attached-user-policies --user-name svc-reporting-sync
aws iam list-user-policies --user-name svc-reporting-sync
aws iam list-groups-for-user --user-name svc-reporting-sync
aws iam create-access-key --user-name svc-reporting-sync
```

Die drei `list`-Befehle müssen leere Listen liefern. Fügt Ihr Konto neue Benutzer automatisch einer Gruppe hinzu, nehmen Sie den Benutzer wieder heraus. Der letzte Befehl gibt `AccessKeyId` und `SecretAccessKey` aus; das Geheimnis wird nicht noch einmal angezeigt. Heben Sie beide für die Ablage unten auf und löschen Sie die Ausgabe aus Ihrem Terminal.

Wählen Sie für den Benutzer einen Namen, der zu Ihren Konten passt und nichts über den Zweck verrät.

## Schritt 3: Verbindung, API-Ziel und Rolle

Setzen Sie die Variablen. Nehmen Sie zuerst die Region Ihrer Workloads; Schritt 5 sagt, wann Sie für eine andere Region wiederholen.

```bash
REGION=eu-central-1
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
```

EventBridge verlangt eine Verbindung mit einer Autorisierung, die der Honeytoken ignoriert. Jeder Wert genügt; erzeugen Sie einen:

```bash
KEY=$(aws secretsmanager get-random-password --password-length 24 --exclude-punctuation --query RandomPassword --output text)
CONN_ARN=$(aws events create-connection --region "$REGION" --name audit-notify-user-conn --authorization-type API_KEY --auth-parameters "{\"ApiKeyAuthParameters\":{\"ApiKeyName\":\"x-api-key\",\"ApiKeyValue\":\"$KEY\"}}" --query ConnectionArn --output text)
DEST_ARN=$(aws events create-api-destination --region "$REGION" --name audit-notify-user-dest --connection-arn "$CONN_ARN" --invocation-endpoint 'Honeytoken-URL' --http-method POST --invocation-rate-limit-per-second 5 --query ApiDestinationArn --output text)
```

EventBridge legt den Schlüssel in einem Secret von Secrets Manager ab, das es selbst verwaltet. Die Grenze von fünf Anfragen pro Sekunde verhindert, dass ein Schwall von Aufrufen zu einem Schwall von Anfragen wird; was EventBridge nicht zustellen konnte, versucht es erneut. Die Rolle ist global, Sie legen sie also einmal an:

```bash
aws iam create-role --role-name audit-notify-user-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam put-role-policy --role-name audit-notify-user-role --policy-name invoke --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"events:InvokeApiDestination\",\"Resource\":\"arn:aws:events:*:$ACCOUNT:api-destination/audit-notify-user-dest/*\"}]}"
```

Die Rolle darf nichts außer diesem Ziel aufrufen, in jeder Region.

## Schritt 4: die Regel

Die Regel erfasst jeden Aufruf des Benutzers. Lesende Aufrufe wie `GetCallerIdentity` erreichen eine Regel nur im Zustand `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`, den nur die AWS CLI und CloudFormation setzen können.

```bash
cat > pattern.json <<EOF
{"detail-type":["AWS API Call via CloudTrail"],"detail":{"userIdentity":{"type":["IAMUser"],"userName":["svc-reporting-sync"]}}}
EOF
aws events put-rule --region "$REGION" --name audit-notify-user-rule --state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS --event-pattern file://pattern.json
```

Das Ziel sendet nur, was Sie brauchen, damit der Request-Body weit unter den 4096 Byte bleibt, die der Honeytoken aufbewahrt. Ein vollständiger CloudTrail-Eintrag passt nicht hinein.

```bash
cat > targets.json <<EOF
[{"Id":"1","Arn":"$DEST_ARN","RoleArn":"arn:aws:iam::$ACCOUNT:role/audit-notify-user-role","InputTransformer":{"InputPathsMap":{"eventName":"\$.detail.eventName","sourceIPAddress":"\$.detail.sourceIPAddress","userAgent":"\$.detail.userAgent","userArn":"\$.detail.userIdentity.arn","userType":"\$.detail.userIdentity.type","accountId":"\$.detail.userIdentity.accountId","region":"\$.detail.awsRegion","time":"\$.time"},"InputTemplate":"{\"eventName\":<eventName>,\"sourceIPAddress\":<sourceIPAddress>,\"userAgent\":<userAgent>,\"userArn\":<userArn>,\"userType\":<userType>,\"accountId\":<accountId>,\"region\":<region>,\"time\":<time>}"}}]
EOF
aws events put-targets --region "$REGION" --rule audit-notify-user-rule --targets file://targets.json
rm pattern.json targets.json
```

`put-targets` meldet `FailedEntryCount`, der 0 sein muss. Heißt es, die Rolle könne nicht übernommen werden, warten Sie nach dem Anlegen der Rolle einige Sekunden und wiederholen Sie den Befehl.

## Schritt 5: weitere Regionen

Wiederholen Sie Schritt 3 ohne die Rolle und dann Schritt 4 für `us-east-1` und für jede weitere Region, die Sie benutzen: Setzen Sie `REGION` und führen Sie die Befehle erneut aus. API-Ziele gibt es nur in manchen Regionen; die Dokumentation von EventBridge listet sie auf.

## Den Schlüssel ablegen

Legen Sie den Schlüssel dort ab, wo er gefunden wird, in der Form, die die AWS CLI liest. Ersetzen Sie die beiden Werte durch die Ausgabe von Schritt 2:

```ini
[default]
aws_access_key_id = ACCESS_KEY_ID
aws_secret_access_key = SECRET_ACCESS_KEY
```

Geeignet sind die Datei `~/.aws/credentials` in einer Sicherung eines Home-Verzeichnisses, eine Deployment-Konfiguration, ein Repository mit Skripten oder eine Notiz mit Zugangsdaten. Vermerken Sie im Szenario, wo Sie ihn abgelegt haben.

## Testen

Richten Sie ein Profil mit dem Schlüssel ein (die CLI fragt die Werte ab, sie bleiben so aus Ihrem Shell-Verlauf) und führen Sie einen Aufruf aus:

```bash
aws configure --profile svc-reporting-sync
aws sts get-caller-identity --profile svc-reporting-sync --region "$REGION"
```

CloudTrail liefert ein Ereignis im Durchschnitt etwa fünf Minuten nach dem Aufruf, garantiert ist das von AWS nicht. Dann zeigt das Szenario einen Incident, und das Event enthält einen Body wie diesen:

```json
{"eventName":"GetCallerIdentity","sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.x ...","userArn":"arn:aws:iam::123456789012:user/NAME","userType":"IAMUser","accountId":"123456789012","region":"eu-central-1","time":"2026-01-01T10:00:00Z"}
```

Schließen Sie den Incident nach dem Test und entfernen Sie das Profil aus `~/.aws/credentials` und `~/.aws/config`.

## Entfernen

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

Die ersten vier führen Sie für jede Region aus. Rolle und Benutzer löschen Sie einmal.

## Grenzen

- **Ohne aufzeichnenden Trail kommt nichts an.** Hält jemand den Trail an oder engt seine Auswahl ein, endet der Alert ohne Anzeichen.
- **Regionen.** Ein Aufruf in einer Region ohne Regel wird nicht gemeldet. Ein Eindringling, der den globalen Endpunkt des Security Token Service benutzt, landet in `us-east-1`; wer einen regionalen Endpunkt benutzt, dort, wo er ihn eingestellt hat.
- **Verzögerung.** Minuten, nicht Sekunden.
- **Wiederholungen.** EventBridge sendet eine Anfrage erneut, wenn es nicht rechtzeitig Erfolg sieht, derselbe Aufruf kann also zweimal gemeldet werden. Der Honeytoken beantwortet jede Anfrage gleich.
- **Der Alert nennt den Honeytoken, nicht den Aufrufer.** Die Adresse des Events ist die des AWS-Dienstes, der den Webhook sendet. Aufrufer, Adresse und User-Agent stehen nur im Anfang des Body, den die Console als Text eines Angreifers zeigt und der in keinem Alert steht.
- **Aufgezeichnet werden nur Anfragen, die bei Ihrem Konto ankommen.** Was ein Eindringling über den Schlüssel erfahren kann, ohne eine Anfrage an Ihr Konto zu senden, hinterlässt dort keine Spur.
- **Sichtbar für jeden, der nachsieht.** Ein Eindringling mit Leserechten in IAM sieht einen Benutzer ohne Rechte, einer mit Leserechten in EventBridge das Ziel samt URL.
