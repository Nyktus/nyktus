# Word-Dokument mit einer Vorlage auf einem entfernten Host

Diese Deception hat keine Datei zum Herunterladen: Sie schreiben das Dokument selbst, damit es zu dem Ort passt, an dem Sie es ablegen, und hängen ihm eine Vorlage an, die auf diesem Host liegt:

```
hostq3xwz7a2kfm4ub6tyc5nre.d.example.net
```

Der Name gehört zu einem DNS-Honeytoken. Word liest beim Öffnen eines Dokuments dessen angehängte Vorlage. Liegt die Vorlage auf einem entfernten Host, löst Word zuerst den Host-Namen auf, was ein Event auslöst. Die Abfrage geschieht auch dann, wenn die Verbindung zum Host danach scheitert oder das Netz sie sperrt.

## Dokument schreiben

Geben Sie dem Dokument einen Inhalt, den ein Eindringling an diesem Ort lesen will, etwa eine Serverliste, einen Netzplan oder Notizen zu einem Projekt. Ein Dokument mit einer einzigen leeren Seite fällt auf. Speichern Sie es als `.docx`.

## Vorlage anhängen

1. Benennen Sie die Datei in `.zip` um und entpacken Sie sie.
2. Fügen Sie in `word/settings.xml` dieses Element unmittelbar vor dem Element `<w:defaultTabStop` ein. Word ist bei der Reihenfolge der Elemente in dieser Datei streng:

   ```
   <w:attachedTemplate r:id="rId1"/>
   ```

3. Legen Sie die Datei `word/_rels/settings.xml.rels` mit diesem Inhalt an, oder ergänzen Sie, falls es sie gibt, die `Relationship`:

   ```
   <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
   <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
     <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///\\hostq3xwz7a2kfm4ub6tyc5nre.d.example.net\templates\normal.dotx" TargetMode="External"/>
   </Relationships>
   ```

4. Packen Sie die Dateien wieder, mit `[Content_Types].xml` zuerst, und benennen Sie die Datei zurück in `.docx` um.

## Dokument ablegen

Legen Sie es dort ab, wo ein Eindringling nach wertvollen Daten sucht, etwa auf einer Dateifreigabe der Finanz- oder Personalabteilung, in einem Dokumentenmanagementsystem oder in einer Sicherung. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

## Testen

Öffnen Sie das Dokument in Word auf einem Rechner mit Zugang zum Internet und aktivieren Sie die Bearbeitung. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Word öffnet Dokumente aus dem Internet und von manchen Netzwerkfreigaben in der geschützten Ansicht, die keine entfernte Vorlage lädt. Erst „Bearbeitung aktivieren“ startet die Abfrage.
- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Andere Programme, etwa LibreOffice oder ein Betrachter im Browser, laden die Vorlage nicht.
- Der Host-Name ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der das Dokument entpackt, kann ihn ungewöhnlich finden.
