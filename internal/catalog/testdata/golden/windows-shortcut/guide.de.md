# Internetverknüpfung

Die Datei `Portal.url` ist eine Windows-Verknüpfung zur URL `https://t.example.net/linkq3xwz7a2kfm4ub6tyc5nre`. Diese URL gehört zu einem URL-Honeytoken: Wer die Verknüpfung öffnet, öffnet die URL im Browser, was ein Event auslöst, und der Browser wird auf das Weiterleitungsziel des Honeytokens oder auf das Standardziel des Triggers weitergeleitet.

## Datei platzieren

1. Geben Sie dem Honeytoken ein Weiterleitungsziel, das zum Namen der Verknüpfung passt, etwa die öffentliche Anmeldeseite eines Dienstes, den Sie nutzen. Wer die Verknüpfung öffnet, sieht diese Seite.
2. Benennen Sie die Datei so um, dass ihr Name etwas Wertvolles verspricht, etwa `VPN-Zugang.url`, `Gehaltsabrechnung.url` oder `Admin-Konsole.url`. Die Endung `.url` muss bleiben.
3. Legen Sie sie dort ab, wo ein Eindringling sich umsieht, etwa auf dem Desktop oder in den Dokumenten eines Kontos, das nur diesem Zweck dient, auf einer Dateifreigabe der IT oder in einem Ordner mit Übergabenotizen.
4. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

## Testen

Öffnen Sie die Verknüpfung auf einem Rechner mit Zugang zum Internet. Innerhalb einer Minute zeigt das Scenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Die Verknüpfung löst nur ein Event aus, wenn jemand sie öffnet. Der Windows-Explorer ruft die URL nicht auf, wenn er den Ordner anzeigt.
- Wer die Eigenschaften der Verknüpfung ansieht oder sie in einem Texteditor öffnet, sieht die URL. Sie nennt die Adresse Ihres Triggers und einen Zufallswert.
