# Fernzugriff von Administratoren

Administratoren erreichen Server über Remotedesktop, SSH, ein Ansible-Inventar und einen VPN-Tunnel. Die folgenden Dateien halten diese Verbindungen fest. Die Dateien teilen sich die Honeytokens der Geschichte, derselbe Host-Name steht also in jeder Datei, die denselben Dienst nennt. Hinter den Namen steht nichts: Konten, Token und Passwörter gibt es nirgends. Sie entscheiden, welche Dateien Sie wo ablegen; eine genügt, und sie müssen nicht beieinander liegen.

## Remotedesktopverbindung

Die Datei `Server.rdp` ist eine gespeicherte Verbindung des Remotedesktop-Clients von Windows zum Server `Honeytoken-Domain-Server`, mit dem Konto `adm.jdoe@corp.example.com`. Der Servername gehört zu einem DNS-Honeytoken: Bevor der Client sich verbindet, löst er den Namen auf, was ein Event auslöst. Dahinter steht kein Server, die Verbindung scheitert also.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Zugängen zu weiteren Systemen sucht, etwa auf dem Desktop oder in den Dokumenten eines administrativen Kontos, das nur diesem Zweck dient, auf einem Jump-Server oder auf einer Dateifreigabe der IT.
2. Benennen Sie sie nach einem Server, den der Eindringling erreichen wollen würde, etwa `Backupserver.rdp` oder `Domaincontroller.rdp`. Die Endung `.rdp` muss bleiben.
3. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Öffnen Sie die Datei auf einem Windows-Rechner mit Zugang zum Internet und klicken Sie auf „Verbinden“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## SSH-Konfiguration mit Jump-Host

Die Datei `config` ist eine SSH-Client-Konfiguration. Sie leitet jede Verbindung zu einem Host unter `corp.example.com` und jede Verbindung zu `jump` über den Jump-Host `Honeytoken-Domain-JumpHost`. Dieser Name gehört zu einem DNS-Honeytoken: Bevor SSH sich verbindet, löst es den Namen auf, und die Abfrage löst ein Event aus. Die Verbindung selbst scheitert, weil hinter dem Namen kein SSH-Server steht.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Zugängen zu weiteren Hosts sucht, zum Beispiel als `~/.ssh/config` eines Kontos auf einem Jump-Server oder einem Administrationsrechner, oder auf einer Dateifreigabe zwischen Skripten und Notizen der IT.
2. Auf einem System, auf dem die Datei als `~/.ssh/config` dient, beschränken Sie sie auf ihren Besitzer: `chmod 600 ~/.ssh/config`. SSH verweigert Konfigurationsdateien, die andere beschreiben können.
3. Legen Sie sie nicht dort ab, wo Kollegen sie für ihre eigene Arbeit nutzen. Jedes legitime `ssh` zu einem Host unter `corp.example.com` würde ein Event auslösen.
4. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben, damit es wiedergefunden und entfernt werden kann.

### Testen

Führen Sie `ssh -F config jump` auf einem Rechner aus, der Namen über das Internet auflöst. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Ansible-Inventar

Die Datei `inventory.ini` ist ein Ansible-Inventar mit den Gruppen `web` und `app`. Die Gruppe `app` enthält den Host `Honeytoken-Domain-Application`. Der Name gehört zu einem DNS-Honeytoken: Ein Playbook, das gegen alle Hosts läuft, oder eine SSH-Verbindung zu diesem Host löst ihn auf, was ein Event auslöst. Dahinter steht kein Server. Die Hosts der Gruppe `web` sind Namen unter `corp.example.com`, die Sie nicht anlegen; stellen Sie sicher, dass es sie in Ihrem Netz nicht gibt, oder ändern Sie sie auf Hosts, die es gibt und die Ansible nicht verwaltet.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach den Servern einer Anwendung sucht: in einem Repository der Automatisierung, auf einem Administrationsserver, in einer Sicherung eines solchen Repositorys.
2. Legen Sie sie nicht dort ab, wo Sie Ansible ausführen. Ein Lauf gegen alle Hosts würde den Namen auflösen und ein Event auslösen.
3. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Führen Sie `ansible -i inventory.ini app -m ping` auf einem Rechner mit Ansible und Zugang zum Internet aus. Der Befehl scheitert nach der Abfrage. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## WireGuard-Konfiguration für einen Tunnel

Die Datei `wg0.conf` ist die Clientkonfiguration eines WireGuard-Tunnels zum Gateway `Honeytoken-Domain-Gateway`. Die Schlüssel sind Zufallswerte in der Form von WireGuard-Schlüsseln. Der Name des Gateways gehört zu einem DNS-Honeytoken: Wer den Tunnel mit `wg-quick up` aufbaut oder die Datei in einen WireGuard-Client importiert, löst den Namen auf, was ein Event auslöst. Dahinter steht kein Gateway, und die Schlüssel gibt es nirgends.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Zugang zum Netz sucht: im Home-Verzeichnis eines Administratorkontos, das nur diesem Zweck dient, in einem Ordner mit VPN-Profilen auf einer Dateifreigabe der IT oder in einer Sicherung eines Arbeitsplatzes.
2. Benennen Sie sie um, wenn der Ort einen anderen Namen nahelegt, etwa `office.conf`. Die Endung `.conf` muss bleiben.
3. Kopieren Sie sie nicht nach `/etc/wireguard`: Ein Systemdienst würde den Tunnel bei jedem Start aufbauen und Events auslösen.
4. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Führen Sie `nslookup Honeytoken-Domain-Gateway` auf einem Rechner mit Zugang zum Internet aus; `sudo wg-quick up ./wg0.conf` auf einem Rechner mit WireGuard wirkt genauso. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Pocket Litter

Die Dateien `shell-history.txt` und `Tickets.csv` enthalten keinen Honeytoken und lösen kein Event aus, was auch mit ihnen geschieht. Sie geben der Geschichte eine glaubhafte Umgebung: Legen Sie sie an denselben Orten ab wie die übrigen Dateien der Geschichte, neben den Dateien, die ein Event auslösen.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Die Host-Namen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Dateien genau liest, kann sie ungewöhnlich finden.
- `wg0.conf`: WireGuard löst den Endpunkt auf, wenn der Tunnel hochkommt. Ein Eindringling, der die Datei nur liest, löst kein Event aus.
