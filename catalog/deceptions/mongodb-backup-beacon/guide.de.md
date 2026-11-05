## Geschichte

Legen Sie in einer MongoDB-Datenbank ein Dokument mit einer Verbindungszeichenfolge an, damit jede Sicherung der Datenbank es enthält. Die Datei `endpoints.js` ist ein Skript für `mongosh`. Es fügt ein Dokument ein, das den Dienst `sync-service` nennt und eine Verbindungszeichenfolge mit dem Konto `svc-sync`, einem zufälligen Passwort und einem Hostnamen enthält. Der Hostname gehört zu einem DNS-Honeytoken. Ein Angreifer, der eine Sicherung stiehlt, die Dokumente liest und sich mit der Zeichenfolge verbindet, löst den Namen auf, und das löst ein Ereignis aus. Hinter dem Namen steht keine Datenbank, und Konto und Passwort gibt es nirgends.

## Umsetzung

1. Legen Sie das DNS-Honeytoken „Datenbank-Host“ an. Ersetzen Sie `Honeytoken-Domain` im Skript durch seinen Namen.
2. Wählen Sie eine Datenbank und eine Collection, die es gibt und die ein Angreifer liest, wenn er nach Verbindungsdaten sucht. Eine Collection für Integrationen oder Dienste passt. Ersetzen Sie die Datenbank `integrations`, die Collection `endpoints` und den Dienstnamen `sync-service` im Skript passend zu Ihren Daten.
3. Führen Sie das Skript einmal aus: `mongosh "mongodb://HOST" --file endpoints.js`, mit der Verbindungszeichenfolge Ihres Servers statt `HOST`. Die Anmeldung braucht das Recht, in die Collection einzufügen.
4. Verwenden Sie für jede Datenbank, deren Sicherungen Sie schützen, ein eigenes Skript.
5. Notieren Sie im Szenario, wo das Dokument liegt.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup Honeytoken-Domain` mit dem Namen des Honeytokens aus. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Um die ganze Kette zu testen, verbinden Sie sich mit `mongosh` über die Zeichenfolge im Dokument.

## Grenzen

- Das Wiederherstellen einer Sicherung führt nichts aus. Ein Ereignis entsteht erst, wenn jemand die Verbindungszeichenfolge verwendet.
- Das Passwort steht im Dokument als Klartext, wie in vielen echten Sammlungen von Verbindungsdaten. Eine Anwendung, die diese Collection über einen Treiber liest, würde den Namen ebenfalls auflösen; wählen Sie eine Collection, die keine Anwendung liest.
- Eine Wiederherstellung in einem Netz, das keine Namen im Internet auflösen kann, erreicht die DNS-Rolle nicht. Das gilt für jedes Beacon in einer Sicherung: Es fängt den Angreifer, der Ihre Sicherung auf einem eigenen Rechner wiederherstellt, aber nicht den, der in einem abgeschotteten Labor arbeitet.
- Wer den Dump nach Hostnamen durchsucht oder sich die Objekte der wiederhergestellten Datenbank ansieht, kann den Namen ungewöhnlich finden.
