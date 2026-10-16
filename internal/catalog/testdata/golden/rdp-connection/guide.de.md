# Remotedesktopverbindung

Die Datei `Server.rdp` ist eine gespeicherte Verbindung des Remotedesktop-Clients von Windows zum Server `serverq3xwz7a2kfm4ub6tyc5nre.d.example.net`, mit dem Konto `adm.jdoe@corp.example.com`. Der Servername gehört zu einem DNS-Honeytoken: Bevor der Client sich verbindet, löst er den Namen auf, was ein Event auslöst. Dahinter steht kein Server, die Verbindung scheitert also.

## Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Zugängen zu weiteren Systemen sucht, etwa auf dem Desktop oder in den Dokumenten eines administrativen Kontos, das nur diesem Zweck dient, auf einem Jump-Server oder auf einer Dateifreigabe der IT.
2. Benennen Sie sie nach einem Server, den der Eindringling erreichen wollen würde, etwa `Backupserver.rdp` oder `Domaincontroller.rdp`. Die Endung `.rdp` muss bleiben.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

## Testen

Öffnen Sie die Datei auf einem Windows-Rechner mit Zugang zum Internet und klicken Sie auf „Verbinden“. Innerhalb einer Minute zeigt das Scenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Der Servername ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Datei in einem Texteditor öffnet, kann ihn ungewöhnlich finden.
