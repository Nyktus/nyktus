# Datenbank-Zugangsdaten in Konfigurationsdateien

Die Konfiguration einer Anwendung hält fest, wie sie ihre Datenbank und ihr Verzeichnis erreicht. Die folgenden Dateien erzählen diese Geschichte an verschiedenen Orten. Die Dateien teilen sich die Honeytokens der Geschichte, derselbe Host-Name steht also in jeder Datei, die denselben Dienst nennt. Hinter den Namen steht nichts: Konten, Token und Passwörter gibt es nirgends. Sie entscheiden, welche Dateien Sie wo ablegen; eine genügt, und sie müssen nicht beieinander liegen.

## Konfigurationsdatei mit Datenbank-Zugangsdaten

Die Datei `config.ini` konfiguriert die Datenbankverbindung einer Anwendung: den Host `Honeytoken-Domain-Database`, die Datenbank `billing`, das Konto `billing_app` und ein zufälliges Passwort. Der Host-Name gehört zu einem DNS-Honeytoken: Ein Client, der sich mit diesen Werten verbindet, löst ihn auf, was ein Event auslöst. Dahinter steht keine Datenbank, die Verbindung scheitert also, und Konto und Passwort gibt es nirgends.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Zugangsdaten sucht: neben einer Anwendung auf einem Server, in einem Repository mit Konfiguration, in einem Deployment-Verzeichnis oder in einer Sicherung davon.
2. Benennen Sie sie um, wenn der Ort einen anderen Namen nahelegt, etwa `database.ini` oder `settings.ini`.
3. Legen Sie sie nicht dort ab, wo eine laufende Anwendung sie liest. Die Anwendung würde den Namen bei jedem Start auflösen und Events auslösen.
4. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Lösen Sie den Host auf einem Rechner mit Zugang zum Internet auf, zum Beispiel mit `nslookup Honeytoken-Domain-Database`. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Umgebungsdatei mit Geheimnissen eines Dienstes

Die Datei `production.env` ist die Umgebungsdatei eines Dienstes. Sie enthält eine Datenbank-URL mit dem Host `Honeytoken-Domain-Database`, der Datenbank `billing`, dem Konto `billing_app` und einem zufälligen Passwort sowie zwei weitere zufällige Geheimnisse. Der Host-Name gehört zu einem DNS-Honeytoken: Ein Client, der sich mit der Datenbank verbindet, löst ihn auf, was ein Event auslöst. Dahinter steht keine Datenbank, und die Geheimnisse gibt es nirgends.

### Datei platzieren

1. Benennen Sie die Datei an dem Ort, an dem Sie sie ablegen, in `.env` um oder in den Namen, den Ihre Deployments verwenden. Der Katalog kann keine Datei mit führendem Punkt benennen.
2. Legen Sie sie dort ab, wo ein Eindringling nach Geheimnissen von Diensten sucht: in einem Repository eines Dienstes, in einem Deployment-Verzeichnis auf einem Server, in einer Sicherung eines solchen Verzeichnisses.
3. Legen Sie sie nicht dort ab, wo ein laufender Dienst sie liest. Der Dienst würde den Namen bei jedem Start auflösen und Events auslösen.
4. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Lösen Sie den Namen mit `nslookup Honeytoken-Domain-Database` auf einem Rechner mit Zugang zum Internet auf, oder verbinden Sie sich mit `psql` mit der URL. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Verbindungsprofil für ein Verzeichnis

Die Datei `ldap.ini` konfiguriert, wie eine Anwendung sich mit ihrem Verzeichnis verbindet: den Server `Honeytoken-Domain-Directory`, das Bind-Konto `billing_app@corp.example.com` und ein zufälliges Passwort. Der Servername gehört zu einem DNS-Honeytoken: Wer sich mit diesen Werten verbindet, löst ihn auf, was ein Event auslöst. Dahinter steht kein Verzeichnis, die Verbindung scheitert also, und Konto und Passwort gibt es nirgends.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Zugangsdaten von Anwendungen sucht: neben einer Anwendung auf einem Server, in einem Repository mit Konfiguration, in einer Sicherung eines Deployment-Verzeichnisses.
2. Benennen Sie sie um, wenn der Ort einen anderen Namen nahelegt, etwa `directory.ini`.
3. Legen Sie sie nicht dort ab, wo eine laufende Anwendung sie liest. Die Anwendung würde den Namen bei jedem Start auflösen und Events auslösen.
4. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Lösen Sie den Namen mit `nslookup Honeytoken-Domain-Directory` auf einem Rechner mit Zugang zum Internet auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Client-Dateien der Datenbank

Die Dateien `pgpass` und `my.cnf` halten die Verbindung zur Datenbank in der Form fest, die die Clients von PostgreSQL und MySQL lesen: den Host `Honeytoken-Domain-Database`, die Datenbank `billing`, das Konto `billing_app` und ein zufälliges Passwort. Ein Client, der sich damit verbindet, löst den Host-Namen auf, was ein Event auslöst. Dahinter steht keine Datenbank, und Konto und Passwort gibt es nirgends.

### Datei platzieren

1. Wählen Sie die Datei, die zum vorgetäuschten Datenbanksystem passt, oder legen Sie beide ab.
2. Nennen Sie sie `.pgpass` und `.my.cnf` und legen Sie sie im Home-Verzeichnis eines Kontos auf einem Anwendungs- oder Administrationsserver ab. Beschränken Sie sie auf ihren Besitzer: `chmod 600 ~/.pgpass ~/.my.cnf`. libpq ignoriert eine `.pgpass`, die andere lesen können.
3. Legen Sie sie nicht im Konto eines Dienstes ab, der sich mit einer echten Datenbank verbindet.
4. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Lösen Sie den Host mit `nslookup Honeytoken-Domain-Database` auf einem Rechner mit Zugang zum Internet auf, oder verbinden Sie sich mit `psql` oder `mysql` und der Datei am Platz. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Die Host-Namen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Dateien genau liest, kann sie ungewöhnlich finden.
