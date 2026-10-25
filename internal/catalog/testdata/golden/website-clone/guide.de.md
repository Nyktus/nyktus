# Skript, das eine Kopie Ihrer Website erkennt

Die Datei `site.js` ist ein Skript für die Seiten Ihrer Website `www.example.com`. Lädt ein Browser eine Seite, die es einbindet, von einem anderen Host, fordert das Skript das unsichtbare Bild `https://t.example.net/beaconq3xwz7a2kfm4ub6tyc5nre` an, was ein Event auslöst. Auf Ihrem eigenen Host tut es nichts. Genau das geschieht, wenn jemand Ihre Seiten samt Skripten auf einen eigenen Server kopiert, um Passwörter von Besuchern zu sammeln.

## Datei platzieren

1. Laden Sie die Datei auf Ihren Webserver hoch, neben die anderen Skripte, und binden Sie sie in die Seiten ein, von denen eine Kopie gemacht würde, vor allem in die Anmeldeseite: `<script src="/site.js"></script>`.
2. Benennen Sie sie um, wenn Ihre Skripte einem anderen Schema folgen, etwa in `main.js`, und passen Sie die Einbindung an.
3. Werden Ihre Seiten auch unter anderen Host-Namen ausgeliefert, die Sie kontrollieren, etwa auf einem Testsystem, ergänzen Sie diese Namen in der Liste am Anfang des Skripts.
4. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

## Testen

Kopieren Sie die Anmeldeseite mit ihren Skripten auf einen anderen Host, oder öffnen Sie sie aus einer lokalen Datei, und laden Sie sie in einem Browser. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Eine Kopie, die die Skripte weglässt oder dieses entfernt, löst kein Event aus. Werkzeuge, die Seiten unverändert kopieren, behalten es.
- Das Skript fordert das Bild nur an, wenn der Host-Name abweicht. Auch ein Testsystem oder eine Vorschau, die nicht in der Liste steht, löst Events aus.
- Die Anfrage zeigt im Header `Referer` die Adresse der Seite, die das Skript geladen hat, sofern der Browser ihn sendet.
