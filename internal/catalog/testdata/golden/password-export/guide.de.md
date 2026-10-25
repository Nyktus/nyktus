# Passwort-Export eines Browsers

Die Datei `Passwords.csv` hat die Spalten, die Chrome, Edge und andere Browser schreiben, wenn der Benutzer gespeicherte Passwörter exportiert. Drei Einträge gehören zum Konto `j.doe`; die Adresse eines davon ist `https://t.example.net/portalq3xwz7a2kfm4ub6tyc5nre`. Diese URL gehört zu einem URL-Honeytoken: Wer die Adresse öffnet, etwa um das Passwort auszuprobieren, löst ein Event aus und wird auf das Weiterleitungsziel des Honeytokens weitergeleitet. Die Passwörter gibt es nirgends.

## Datei platzieren

1. Geben Sie dem Honeytoken ein Weiterleitungsziel, das zum Eintrag passt, etwa die öffentliche Anmeldeseite eines Dienstes, den Sie nutzen.
2. Legen Sie die Datei dort ab, wo ein Benutzer einen Export liegen lässt, den er hätte löschen sollen: in den Downloads oder Dokumenten eines Kontos, das nur diesem Zweck dient, oder auf einer Freigabe der IT.
3. Passen Sie die Einträge an, wenn Ihr eigenes Namensschema von `wiki`, `build` und `portal` abweicht.
4. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

## Testen

Öffnen Sie die URL des dritten Eintrags in einem Browser auf einem Rechner mit Zugang zum Internet. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur wer die Adresse öffnet, löst ein Event aus. Das Lesen der Datei löst keines aus.
- Die ersten beiden Einträge verweisen auf Namen unter `corp.example.com`, die Sie nicht über Nyktus kontrollieren. Stellen Sie sicher, dass niemand diese Passwörter irgendwo einträgt, oder dass diese Namen in Ihrem Netz nicht existieren.
- Wer die Datei liest, sieht die URL. Sie nennt die Adresse Ihres Triggers und einen Zufallswert.
