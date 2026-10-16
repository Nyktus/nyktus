# Browser-Lesezeichen

Die Datei `bookmarks.html` ist ein Export von Browser-Lesezeichen in dem Format, das jeder gängige Browser schreibt und importiert. In der Lesezeichenleiste enthält ein Ordner `Example Ltd` den Link `VPN self\-service`, der auf `https://t.example.net/portalq3xwz7a2kfm4ub6tyc5nre` führt. Diese URL gehört zu einem URL-Honeytoken: Wer dem Link folgt, löst ein Event aus und wird auf das Weiterleitungsziel des Honeytokens weitergeleitet.

## Datei platzieren

1. Geben Sie dem Honeytoken ein Weiterleitungsziel, das zum Namen des Portals passt, etwa die öffentliche Anmeldeseite eines Dienstes, den Sie nutzen.
2. Legen Sie die Datei entweder als Export ab, zum Beispiel in den Dokumenten eines Kontos, das nur diesem Zweck dient, oder in einer Sicherung eines Benutzerprofils, oder importieren Sie sie in den Browser eines solchen Kontos, damit der Link in dessen Lesezeichen erscheint.
3. Ergänzen Sie eigene Lesezeichen, etwa die öffentlichen Seiten Ihrer Organisation, damit die Datei nicht nur einen Ordner enthält.
4. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

## Testen

Öffnen Sie die Datei in einem Browser und folgen Sie dem Link, oder importieren Sie sie und öffnen Sie das Lesezeichen. Innerhalb einer Minute zeigt das Scenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Wer die Datei öffnet, sieht die Lesezeichen; erst wer dem Link folgt, löst ein Event aus.
- Wer die Datei liest, sieht die URL. Sie nennt die Adresse Ihres Triggers und einen Zufallswert.
