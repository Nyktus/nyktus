## Geschichte

Legen Sie die Seite einer Zertifizierungsstelle dort ab, wo ein Angreifer nach Wegen zu Zertifikaten sucht. Die Datei `Certificate-templates.html` ist eine interne Seite der Stelle `Example Issuing CA 01`. Sie listet die üblichen Zertifikatvorlagen auf und verweist auf eine Anforderungsseite. Die Datei `Certificate-enrollment.html` enthält denselben Link als Lesezeichen für den Browser. Die URL des Links gehört zu einem URL-Honeytoken: Wer dem Link folgt, löst ein Ereignis aus und wird auf das Weiterleitungsziel des Honeytokens umgeleitet.

## Umsetzung

1. Legen Sie das URL-Honeytoken „Anforderungsseite“ an. Ersetzen Sie `Honeytoken-URL` in beiden Dateien durch seine URL. Geben Sie dem Honeytoken ein Weiterleitungsziel, das zur Seite passt, etwa die öffentliche Seite Ihrer Organisation.
2. Ersetzen Sie den Namen `Example Issuing CA 01` durch einen Namen, der zu Ihrer Umgebung passt. Wenn Ihre Zertifizierungsstelle die Standardvorlagen von Windows aus dem Angebot genommen hat, ändern Sie die Liste auf die Vorlagen, die sie anbietet.
3. Legen Sie die Seite dort ab, wo ein Angreifer nach Wegen zu Zertifikaten sucht: auf einer Dateifreigabe der IT, neben der Dokumentation der Public-Key-Infrastruktur oder in den Dokumenten eines Kontos, das nur diesem Zweck dient.
4. Importieren Sie die Lesezeichendatei in den Browser eines solchen Kontos, oder legen Sie sie als Export ab, zum Beispiel in einer Sicherung des Profils.
5. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `curl Honeytoken-URL` aus, mit der URL des Honeytokens statt des Platzhalters. Die URL steht in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Erscheint kein Incident, prüfen Sie, ob der Rechner die Adresse des Triggers von Nyktus erreicht.

## Grenzen

- Das Öffnen der Seite oder der Lesezeichendatei löst kein Ereignis aus; erst das Folgen des Links tut es.
- Wer die Datei liest, sieht die URL. Sie nennt die Adresse Ihres Triggers und einen Zufallswert.
