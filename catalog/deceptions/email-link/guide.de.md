## Geschichte

Legen Sie eine gespeicherte E-Mail dort ab, wo ein Angreifer nach Post sucht. Die Datei `message.html` ist eine E-Mail als HTML, so wie ein Mailprogramm sie speichert oder exportiert. Sie hat den Betreff `Mailbox storage almost full`, einen Link mit dem Text `Open mailbox overview` und ein unsichtbares Bild von einem Pixel. Beide URLs gehören zu Honeytokens: Wer dem Link folgt, löst ein Ereignis aus und wird auf das Weiterleitungsziel des Honeytokens umgeleitet; auch das Laden des Bildes löst ein Ereignis aus.

## Umsetzung

Jeder Platzhalter in der Datei gehört zu einem Honeytoken:

- `Honeytoken-URL-Link`: „Link“, der Link `Open mailbox overview`
- `Honeytoken-URL-Pixel`: „Bild“, das unsichtbare Bild

1. Legen Sie die zwei URL-Honeytokens an. Ersetzen Sie jeden Platzhalter in der Datei durch die URL seines Honeytokens.
2. Geben Sie dem Honeytoken „Link“ ein Weiterleitungsziel, das zum Text des Links passt, etwa die öffentliche Anmeldeseite eines Dienstes, den Sie nutzen.
3. Legen Sie die Datei dort ab, wo ein Angreifer nach Post sucht: in einem Export eines Postfachs, in einem Ordner mit gespeicherten Nachrichten in den Dokumenten eines Kontos, das nur diesem Zweck dient, oder auf einer Freigabe mit Mailsicherungen.
4. Benennen Sie sie wie die Exporte an diesem Ort, zum Beispiel nach dem Betreff.
5. Notieren Sie im Szenario, wo die Datei liegt.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `curl Honeytoken-URL-Link` und `curl Honeytoken-URL-Pixel` aus, mit der URL des jeweiligen Honeytokens statt des Platzhalters. Die URLs stehen in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Erscheint kein Incident, prüfen Sie, ob der Rechner die Adresse des Triggers von Nyktus erreicht.

## Grenzen

- Das Öffnen der Datei in einem Browser löst von selbst ein Ereignis aus, weil der Browser das Bild lädt. In einem Editor geschieht das nicht.
- Mail-Gateways und Vorschauen können das Bild und den Link laden, ohne dass jemand die Nachricht liest. Versenden Sie die Datei nicht per E-Mail.
- Wer die Datei liest, sieht die URLs. Sie nennen die Adresse Ihres Triggers und einen Zufallswert.
