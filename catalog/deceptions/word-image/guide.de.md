## Geschichte

Verknüpfen Sie ein Bild in einem Word-Dokument, das Sie selbst schreiben. Diese Deception hat keine Datei zum Herunterladen, damit das Dokument dorthin passt, wo Sie es ablegen. Die URL des Bildes gehört zu einem Bild-Honeytoken. Es antwortet immer mit einem unsichtbaren Bild von einem Pixel. Word lädt ein verknüpftes Bild von seiner URL, sooft es das Dokument öffnet, und die Anfrage löst ein Ereignis aus.

## Umsetzung

1. Legen Sie das Bild-Honeytoken „Bild“ an. Seine URL ersetzt unten `Honeytoken-URL`.
2. Schreiben Sie das Dokument. Geben Sie ihm Inhalt, den ein Angreifer an dem Ort lesen will, an dem Sie es ablegen, etwa Gehaltszahlen, eine Liste von Ansprechpartnern für Notfälle oder den Plan eines Projekts. Ein Dokument, das nur ein Bild enthält, fällt auf.
3. Setzen Sie den Cursor an eine unauffällige Stelle, zum Beispiel ans Ende des Dokuments, und drücken Sie **Strg+F9**. Word fügt ein leeres Feld `{ }` ein.
4. Schreiben Sie zwischen die Klammern, mit der URL des Honeytokens statt des Platzhalters:

   ```
   INCLUDEPICTURE "Honeytoken-URL" \d
   ```

   `\d` verhindert, dass Word das Bild im Dokument speichert, sodass es bei jedem Öffnen neu geladen wird.
5. Drücken Sie **F9**, um das Feld zu aktualisieren, und speichern Sie das Dokument als `.docx`.
6. Legen Sie das Dokument dort ab, wo ein Angreifer nach wertvollen Daten sucht, etwa auf einer Dateifreigabe der Finanz- oder Personalabteilung, in einem Dokumentenmanagementsystem oder in einer Sicherung.
7. Notieren Sie im Szenario, wo das Dokument liegt.

## Testen

Öffnen Sie das Dokument in Word auf einem Rechner mit Internetzugang und klicken Sie auf `Enable Editing`. Die Beschriftungen stehen so, wie sie in der englischen Oberfläche von Word heißen; in einer anderen Sprache lauten sie anders. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Um nur das Honeytoken zu prüfen, führen Sie `curl Honeytoken-URL` mit der URL des Honeytokens aus.

## Grenzen

- Word öffnet Dokumente aus dem Internet und von manchen Netzfreigaben in der `Protected View`, die keine Bilder lädt. Erst `Enable Editing` sendet die Anfrage.
- Mail-Gateways und Vorschauen können das Bild laden, ohne dass jemand das Dokument öffnet. Versenden Sie das Dokument nicht per E-Mail.
- Andere Programme, etwa LibreOffice oder ein Betrachter im Browser, laden verknüpfte Bilder möglicherweise nicht.
