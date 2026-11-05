## Geschichte

Legen Sie in Ihrer Website ein Skript ab, das eine Kopie erkennt. Die Datei `site.js` ist ein Skript für die Seiten Ihrer Website. Lädt ein Browser eine Seite, die es einbindet, von einem anderen Host, fordert das Skript ein unsichtbares Bild an, und das löst ein Ereignis aus. Auf Ihrem eigenen Host tut es nichts. Genau das geschieht, wenn jemand Ihre Seiten samt Skripten auf einen eigenen Server kopiert, um Passwörter von Besuchern einzusammeln.

## Umsetzung

1. Legen Sie das Bild-Honeytoken „Bild“ an. Ersetzen Sie `Honeytoken-URL` in `site.js` durch seine URL.
2. Ersetzen Sie `www.example.com` am Anfang des Skripts durch den Hostnamen Ihrer Website. Werden Ihre Seiten auch unter anderen Hostnamen ausgeliefert, die Sie betreiben, etwa auf einem Testsystem, nehmen Sie diese Namen in dieselbe Bedingung auf.
3. Laden Sie die Datei auf Ihren Webserver, neben die anderen Skripte, und binden Sie sie in die Seiten ein, von denen jemand eine Kopie anlegen würde, vor allem in die Anmeldeseite: `<script src="/site.js"></script>`.
4. Wenn Ihre Skripte einem anderen Namensschema folgen, benennen Sie die Datei um, zum Beispiel in `main.js`, und passen Sie die Einbindung an.
5. Notieren Sie im Szenario, wo die Datei liegt.

## Testen

Kopieren Sie die Anmeldeseite samt Skripten auf einen anderen Host oder öffnen Sie sie aus einer lokalen Datei und laden Sie sie in einem Browser. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Um nur das Honeytoken zu prüfen, führen Sie auf einem Rechner mit Internetzugang `curl Honeytoken-URL` mit der URL des Honeytokens aus.

## Grenzen

- Eine Kopie, die die Skripte weglässt oder dieses entfernt, löst kein Ereignis aus. Werkzeuge, die Seiten unverändert kopieren, behalten es.
- Das Skript fordert das Bild nur an, wenn der Hostname abweicht. Ein Testsystem oder eine Vorschau, die nicht in der Bedingung steht, löst ebenfalls Ereignisse aus.
- Die Anfrage zeigt im Header `Referer` die Adresse der Seite, die das Skript geladen hat, sofern der Browser ihn sendet.
