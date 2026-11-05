## Geschichte

Legen Sie den Zugang zu einer Container-Registry, einem Kubernetes-Cluster und dem Zustand der Infrastruktur dort ab, wo ein Angreifer ihn sucht. Die Konfiguration eines Arbeitsplatzes oder Build-Servers enthält diesen Zugang. Jeder Dienst hat einen Hostnamen, der zu einem DNS-Honeytoken gehört. Wer den Zugang verwendet, löst den Namen auf, und das löst ein Ereignis aus. Hinter den Namen steht nichts, die Aufrufe scheitern also, und Konten, Token und Passwörter gibt es nirgends. Eine Datei genügt, und die Dateien müssen nicht beieinander liegen. Die Datei `README.md` enthält keinen Honeytoken. Sie gibt der Geschichte eine glaubhafte Umgebung.

## Umsetzung

Jeder Platzhalter in den Dateien gehört zu einem Honeytoken:

- `Honeytoken-Domain-Registry`: „Registry“, in `config.json`
- `Honeytoken-Domain-Api`: „API-Server“, in `config`
- `Honeytoken-Domain-State`: „State-Backend“, in `backend.tf`

1. Legen Sie die drei DNS-Honeytokens an.
2. Ersetzen Sie jeden Platzhalter durch den Namen seines Honeytokens.
3. Legen Sie die Dateien dort ab, wo ein Angreifer nach Zugängen zur Plattform sucht, Datei für Datei.
4. `config.json`: als `~/.docker/config.json` im Home-Verzeichnis eines Kontos auf einem Build-Server oder Arbeitsplatz, am besten eines Kontos, das nur diesem Zweck dient, oder in einer Sicherung eines solchen Verzeichnisses.
5. `config`: als `~/.kube/config` im Home-Verzeichnis eines solchen Kontos. Beschränken Sie sie mit `chmod 600 ~/.kube/config` auf ihren Besitzer.
6. `backend.tf`: in einem Repository oder Verzeichnis mit Terraform-Code, den ein Angreifer lesen würde, etwa einem Repository der Infrastruktur, einem Ordner eines Administrationsservers oder einer Sicherung eines solchen Ordners.
7. `README.md`: neben den anderen Dateien der Geschichte.
8. Hat das Konto bereits eine `config.json`, fügen Sie den Eintrag für die Registry in deren Objekt `auths` ein. Hat es bereits eine `~/.kube/config`, fügen Sie die drei Einträge in deren Listen ein. So funktionieren die übrigen Registries und Cluster weiter.
9. Legen Sie die Dateien nicht dort ab, wo ein laufender Build, Job oder eine Pipeline sie liest oder wo Sie Terraform ausführen. Jeder Lauf würde den Namen auflösen und ein Ereignis auslösen.
10. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup` mit dem Namen eines Honeytokens aus, zum Beispiel `nslookup Honeytoken-Domain-Registry`. Die Namen stehen in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Die Werkzeuge haben dieselbe Wirkung und scheitern nach der Abfrage: `docker pull Honeytoken-Domain-Registry/app:latest`, `kubectl --kubeconfig ./config get pods` oder `terraform init` in einem Verzeichnis mit `backend.tf`.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Die Hostnamen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Wer die Dateien genau liest, kann sie ungewöhnlich finden.
- Das Lesen einer Datei löst kein Ereignis aus; die Verwendung des Zugangs tut es.
