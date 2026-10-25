# Terraform-Backend mit Zugangsdaten

Die Datei `backend.tf` konfiguriert ein HTTP-Backend für den State des Projekts `platform-prod` auf `stateq3xwz7a2kfm4ub6tyc5nre.d.example.net`, mit dem Konto `terraform` und einem zufälligen Passwort. Der Host-Name gehört zu einem DNS-Honeytoken: `terraform init`, `plan` und `apply` lösen ihn auf, was ein Event auslöst. Dahinter steht kein Backend, die Befehle scheitern also, und Konto und Passwort gibt es nirgends.

## Datei platzieren

1. Legen Sie die Datei in ein Repository oder Verzeichnis mit Terraform-Code ab, das ein Eindringling lesen würde: ein Repository der Infrastruktur, ein Ordner eines Administrationsservers, eine Sicherung eines solchen Ordners.
2. Legen Sie sie nicht in ein Verzeichnis, in dem Sie oder eine Pipeline Terraform ausführen. Jeder Lauf würde den Namen auflösen und ein Event auslösen.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

## Testen

Führen Sie `terraform init` in einem Verzeichnis mit der Datei auf einem Rechner mit Terraform und Zugang zum Internet aus. Der Befehl scheitert nach der Abfrage. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Der Host-Name des Backends ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Datei genau liest, kann ihn ungewöhnlich finden.
