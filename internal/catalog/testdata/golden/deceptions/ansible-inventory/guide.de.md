# Ansible-Inventar

Die Datei `inventory.ini` ist ein Ansible-Inventar mit den Gruppen `web` und `app`. Die Gruppe `app` enthält den Host `applicationq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Der Name gehört zu einem DNS-Honeytoken: Ein Playbook, das gegen alle Hosts läuft, oder eine SSH-Verbindung zu diesem Host löst ihn auf, was ein Event auslöst. Dahinter steht kein Server. Die Hosts der Gruppe `web` sind Namen unter `corp.example.com`, die Sie nicht anlegen; stellen Sie sicher, dass es sie in Ihrem Netz nicht gibt, oder ändern Sie sie auf Hosts, die es gibt und die Ansible nicht verwaltet.

## Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach den Servern einer Anwendung sucht: in einem Repository der Automatisierung, auf einem Administrationsserver, in einer Sicherung eines solchen Repositorys.
2. Legen Sie sie nicht dort ab, wo Sie Ansible ausführen. Ein Lauf gegen alle Hosts würde den Namen auflösen und ein Event auslösen.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

## Testen

Führen Sie `ansible -i inventory.ini app -m ping` auf einem Rechner mit Ansible und Zugang zum Internet aus. Der Befehl scheitert nach der Abfrage. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Der Name des Servers ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Datei genau liest, kann ihn ungewöhnlich finden.
