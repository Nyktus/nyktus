# Runbook zur Prüfung der Replikation

Die Datei `Replication-check.txt` ist ein Runbook eines Administrators für die Replikation der Domain `corp.example.com`. Zwei seiner Befehle nennen den Domänencontroller `controllerq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Der Name gehört zu einem DNS-Honeytoken: Wer einen der Befehle ausführt, löst ihn auf, was ein Event auslöst. Dahinter steht kein Controller.

## Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach der Struktur der Domain sucht: auf einem Domänencontroller oder Administrationsserver, auf einer Dateifreigabe der IT, in den Dokumenten eines Kontos, das nur diesem Zweck dient.
2. Ändern Sie `Contact` auf ein Team, das es gibt.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

## Testen

Lösen Sie den Namen mit `nslookup controllerq3xwz7a2kfm4ub6tyc5nre.d.example.net` auf einem Rechner mit Zugang zum Internet auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Der Name des Controllers ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Datei genau liest, kann ihn ungewöhnlich finden.
- Der Controller gehört nicht zu Ihrer Domain. Ein Eindringling, der den Namen mit der Liste der Controller vergleicht, kann ihn ungewöhnlich finden.
