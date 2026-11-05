## Geschichte

Legen Sie Verbindungen von Administratoren dort ab, wo ein Angreifer nach Zugängen zu weiteren Systemen sucht. Vier Dateien nennen Server, die es nicht gibt: eine Remotedesktopverbindung, eine SSH-Konfiguration, ein Ansible-Inventar und eine WireGuard-Konfiguration. Jeder Servername gehört zu einem DNS-Honeytoken. Wer sich mit einer Datei verbindet, löst den Namen auf, und die Abfrage löst ein Ereignis aus; die Verbindung scheitert, weil hinter dem Namen kein Server steht. Zwei weitere Dateien, `shell-history.txt` und `Tickets.csv`, enthalten keinen Honeytoken. Sie geben der Geschichte eine glaubhafte Umgebung.

## Umsetzung

Jeder Platzhalter in den Dateien gehört zu einem Honeytoken:

- `Honeytoken-Domain-Server`: „Server“, in `Server.rdp`
- `Honeytoken-Domain-JumpHost`: „Jump-Host“, in `config`
- `Honeytoken-Domain-Application`: „Anwendungsserver“, in `inventory.ini`
- `Honeytoken-Domain-Gateway`: „VPN-Gateway“, in `wg0.conf`

1. Legen Sie die vier DNS-Honeytokens an.
2. Ersetzen Sie jeden Platzhalter durch den Namen seines Honeytokens. Passen Sie Kontonamen, die Domain `corp.example.com` und Passwörter an Ihre Umgebung an.
3. Legen Sie die Dateien dort ab, wo ein Angreifer nach Zugängen sucht: auf dem Desktop eines Administratorkontos, das nur diesem Zweck dient, auf einem Jump-Server, in einem Repository der Automatisierung oder auf einer Dateifreigabe der IT. Eine Datei genügt, und die Dateien müssen nicht beieinander liegen. Legen Sie `shell-history.txt` und `Tickets.csv` neben die anderen.
4. `Server.rdp`: Benennen Sie die Datei nach einem Server, den ein Angreifer erreichen will, etwa `Backup server.rdp`. Die Endung `.rdp` muss bleiben.
5. `config`: Verwenden Sie die Datei als `~/.ssh/config` nur dort, wo niemand arbeitet, denn jedes `ssh` zu einem Host unter `corp.example.com` löst ein Ereignis aus. Beschränken Sie sie mit `chmod 600 ~/.ssh/config` auf ihren Besitzer; SSH verweigert Konfigurationsdateien, die andere beschreiben können.
6. `inventory.ini`: Legen Sie die Datei nicht dort ab, wo Sie Ansible ausführen, denn ein Lauf gegen alle Hosts löst den Namen auf. Die Hosts der Gruppe `web` sind Namen unter `corp.example.com`; stellen Sie sicher, dass es sie in Ihrem Netz nicht gibt.
7. `wg0.conf`: Kopieren Sie die Datei nicht nach `/etc/wireguard`, denn ein Systemdienst würde den Tunnel bei jedem Start aufbauen. Die Endung `.conf` muss bleiben.
8. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup` mit dem Namen eines Honeytokens aus, zum Beispiel `nslookup Honeytoken-Domain-Server`. Die Namen stehen in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Erscheint kein Incident, prüfen Sie, ob der Rechner Namen über einen Resolver auflöst, der die DNS-Rolle von Nyktus erreicht (siehe „Grenzen“).

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Die Hostnamen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Wer die Dateien genau liest, kann sie ungewöhnlich finden.
- Wer eine Datei nur liest, löst kein Ereignis aus; die Abfrage entsteht erst, wenn ein Programm den Namen verwendet. WireGuard löst den Endpunkt auf, sobald der Tunnel hochkommt.
