## Geschichte

Fügen Sie einem PDF, das Sie selbst schreiben, einen Link und eine Aktion hinzu. Diese Deception hat keine Datei zum Herunterladen, damit das PDF dorthin passt, wo Sie es ablegen. Ein PDF kann beim Darstellen kein entferntes Bild laden, es gibt also kein Bild, das Sie einsetzen können; der Trigger ist ein Link und eine Aktion. Wer den Link anklickt, löst ein Ereignis aus. Die Aktion startet beim Öffnen des Dokuments und nennt ein DNS-Honeytoken, das ein Ereignis auslöst, wenn das Leseprogramm den Namen auflöst.

## Umsetzung

1. Legen Sie das URL-Honeytoken „Link“ und das DNS-Honeytoken „Host“ an. Die URL ersetzt unten `Honeytoken-URL`, der Name ersetzt `Honeytoken-Domain`.
2. Schreiben Sie das Dokument. Geben Sie ihm Inhalt, den ein Angreifer lesen will, etwa eine Rechnung, den Entwurf eines Vertrags oder einen Netzplan, und einen passenden Namen.
3. Legen Sie einen Link über die ganze erste Seite. Wer irgendwo auf die Seite klickt, wird auf das Weiterleitungsziel des Honeytokens umgeleitet; geben Sie ihm ein Ziel, das zum Dokument passt. Der Link öffnet diese URL:

   ```
   Honeytoken-URL
   ```

   Verwenden Sie in Adobe Acrobat, LibreOffice Draw oder einem anderen Editor das Werkzeug für Links, ziehen Sie ein Rechteck über die ganze Seite und wählen Sie `Open a web page` mit dieser URL. Machen Sie den Rahmen unsichtbar. In der Datei ist der Link eine Annotation der Seite:

   ```
   << /Type /Annot /Subtype /Link
      /Rect [0 0 595 842]
      /Border [0 0 0]
      /A << /S /URI /URI (Honeytoken-URL) >>
   >>
   ```

4. Fügen Sie eine Aktion hinzu, die beim Öffnen des Dokuments startet. Sie nennt diesen Host:

   ```
   Honeytoken-Domain
   ```

   Öffnen Sie in Acrobat die Seiteneigenschaften, wählen Sie `Actions`, den Auslöser `Page Open` und die Aktion `Open a web link` mit der Adresse `https://Honeytoken-Domain/`. In der Datei gehört die Aktion zum Katalogobjekt des Dokuments:

   ```
   /OpenAction << /S /URI /URI (https://Honeytoken-Domain/) >>
   ```

   Ein Werkzeug wie `qpdf` oder `mutool` zeigt und bearbeitet die Objekte.
5. Legen Sie das PDF dort ab, wo ein Angreifer nach wertvollen Daten sucht.
6. Notieren Sie im Szenario, wo das Dokument liegt.

## Testen

Öffnen Sie das PDF auf einem Rechner mit Internetzugang und klicken Sie auf die Seite. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Um die Honeytokens allein zu prüfen, führen Sie `curl Honeytoken-URL` und `nslookup Honeytoken-Domain` mit der URL und dem Namen der Honeytokens aus.

## Grenzen

- Leseprogramme unterscheiden sich. Viele fragen nach, bevor sie einen Link aus einer Aktion öffnen, und manche lösen den Hostnamen vor der Nachfrage auf, andere nicht. Sehen Sie die Abfrage als Zugabe; der Klick auf den Link ist der verlässliche Trigger.
- Ein Leseprogramm, das alle Verbindungen von Dokumenten blockiert, oder ein Betrachter im Browser, der Aktionen ignoriert, löst kein Ereignis aus.
- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Wer das PDF in einem Editor öffnet, sieht die URL und den Hostnamen.
- Die Beschriftungen der Editoren stehen so, wie sie in deren englischer Oberfläche heißen.
