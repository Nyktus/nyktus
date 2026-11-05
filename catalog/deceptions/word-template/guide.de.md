## Geschichte

Hängen Sie an ein Word-Dokument, das Sie selbst schreiben, eine Vorlage auf einem entfernten Host an. Diese Deception hat keine Datei zum Herunterladen, damit das Dokument dorthin passt, wo Sie es ablegen. Der Name des Hosts gehört zu einem DNS-Honeytoken. Word liest die angehängte Vorlage eines Dokuments, wenn es das Dokument öffnet. Liegt die Vorlage auf einem entfernten Host, löst Word zuerst den Hostnamen auf, und das löst ein Ereignis aus. Die Abfrage geschieht auch dann, wenn die Verbindung zum Host danach scheitert oder das Netz sie blockiert.

## Umsetzung

1. Legen Sie das DNS-Honeytoken „Host“ an. Sein Name ersetzt unten `Honeytoken-Domain`.
2. Schreiben Sie das Dokument. Geben Sie ihm Inhalt, den ein Angreifer an dem Ort lesen will, an dem Sie es ablegen, etwa eine Serverliste, einen Netzplan oder Notizen zu einem Projekt. Ein Dokument mit einer einzigen leeren Seite fällt auf. Speichern Sie es als `.docx`.
3. Benennen Sie die Datei in `.zip` um und entpacken Sie sie.
4. Fügen Sie in `word/settings.xml` dieses Element unmittelbar vor dem Element `<w:defaultTabStop` ein. Word ist bei der Reihenfolge der Elemente in dieser Datei streng:

   ```
   <w:attachedTemplate r:id="rId1"/>
   ```

5. Legen Sie die Datei `word/_rels/settings.xml.rels` mit diesem Inhalt an, oder fügen Sie die `Relationship` ein, wenn die Datei schon besteht. Verwenden Sie den Namen des Honeytokens statt des Platzhalters:

   ```
   <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
   <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
     <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///\\Honeytoken-Domain\templates\normal.dotx" TargetMode="External"/>
   </Relationships>
   ```

6. Packen Sie die Dateien wieder ein, mit `[Content_Types].xml` zuerst, und benennen Sie die Datei zurück in `.docx` um.
7. Legen Sie das Dokument dort ab, wo ein Angreifer nach wertvollen Daten sucht, etwa auf einer Dateifreigabe der Finanz- oder Personalabteilung, in einem Dokumentenmanagementsystem oder in einer Sicherung.
8. Notieren Sie im Szenario, wo das Dokument liegt.

## Testen

Öffnen Sie das Dokument in Word auf einem Rechner mit Internetzugang und klicken Sie auf `Enable Editing`. Die Beschriftungen stehen so, wie sie in der englischen Oberfläche von Word heißen; in einer anderen Sprache lauten sie anders. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Um nur die Namensauflösung zu prüfen, führen Sie `nslookup Honeytoken-Domain` mit dem Namen des Honeytokens aus.

## Grenzen

- Word öffnet Dokumente aus dem Internet und von manchen Netzfreigaben in der `Protected View`, die keine entfernte Vorlage lädt. Erst `Enable Editing` startet die Abfrage.
- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Andere Programme, etwa LibreOffice oder ein Betrachter im Browser, laden die Vorlage nicht.
- Der Hostname ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Wer das Dokument entpackt, kann ihn ungewöhnlich finden.
