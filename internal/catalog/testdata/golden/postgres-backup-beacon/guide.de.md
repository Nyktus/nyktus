# PostgreSQL-Objekte, die in jeder Sicherung mitreisen

Die Deception hängt den Trigger an Ihre Sicherung selbst. Ein Eindringling, der einen Dump Ihrer Datenbank stiehlt, stellt ihn auf einem eigenen Rechner wieder her, wo ein Wiederherstellungsskript, das nur auf Ihren Host zeigt, nie liefe. Beide Dateien sind SQL für Ihre Datenbank mit dem DNS-Honeytoken-Host `databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Sie führen sie einmal aus; jeder Dump, den Sie danach ziehen, trägt die Objekte. Keine der Dateien legt eine Tabelle mit Daten an, und keine ändert Daten.

## Das Objekt, das bei der Wiederherstellung auslöst

`restore-hook.sql` legt die Funktion `refresh_catalog_stats` und die Materialized View `catalog_stats` an, die sie aufruft. Ein Dump enthält die View ohne Inhalt und aktualisiert sie bei der Wiederherstellung, im Custom- und im Verzeichnisformat ebenso wie in einem Plain-Dump. Die Aktualisierung ruft die Funktion auf, und ihr Verbindungsversuch mit `dblink` löst den Host-Namen auf, was ein Event auslöst. Das Anlegen der View in Ihrer eigenen Datenbank führt die Funktion einmal aus, die Datei testet sich also selbst.

1. Prüfen Sie, dass die Erweiterung `dblink` verfügbar ist: Sie gehört je nach Distribution zum Paket `postgresql-contrib` oder zum Server selbst. Die Funktion nennt `public.dblink_connect`, weil eine Wiederherstellung mit leerem Suchpfad läuft.
2. Führen Sie die Datei in Ihrer Datenbank aus: `psql -d DATENBANK -f restore-hook.sql`. Die Rolle braucht das Recht, eine Erweiterung und Objekte im Schema `public` anzulegen.
3. Wählen Sie `FunctionName` und `ViewName` beim Anwenden der Deception so, dass sie zu Ihrem Schema passen. Beide stehen im Dump.

## Das Objekt, das bei einer Abfrage auslöst

`foreign-table.sql` legt eine Fremdtabelle `customer_payment_tokens` an, die auf eine entfernte Datenbank zeigt. Sie gehört zum Schema, übersteht jedes Dump-Format und löst den Host-Namen nur auf, wenn jemand die Tabelle abfragt, etwa bei der Suche nach Tabellen mit wertvollen Namen.

1. Prüfen Sie, dass die Erweiterung `postgres_fdw` verfügbar ist.
2. Führen Sie die Datei in Ihrer Datenbank aus. Wählen Sie für die Tabelle einen Namen, den ein Eindringling lesen will.

## Testen

Ziehen Sie einen Dump mit `pg_dump DATENBANK > dump.sql` und stellen Sie ihn auf einem Rechner mit Zugang zum Internet in einer leeren Datenbank wieder her: `psql -d TEST -f dump.sql`. Innerhalb einer Minute zeigt das Szenario einen Incident. Fragen Sie danach die Fremdtabelle mit `SELECT * FROM customer_payment_tokens` ab, für einen zweiten. Schließen Sie die Incidents nach dem Test. Setzen Sie je Datenbank oder Sicherungssatz eine eigene Deception ein, damit ein Incident zeigt, welche Daten gestohlen wurden. Informieren Sie Ihre Datenbankadministratoren: Auch eine Test-Wiederherstellung auf einem Rechner mit Internetzugang löst ein Event aus.

## Grenzen

- Eine Wiederherstellung in einem Netz, das keine Namen im Internet auflösen kann, erreicht die DNS-Rolle nicht. Das gilt für jedes Beacon in einer Sicherung: Es erwischt den Eindringling, der Ihre Sicherung auf einem eigenen Rechner wiederherstellt, nicht den, der in einem abgeschotteten Labor arbeitet.
- Wer den Dump nach Host-Namen durchsucht oder die Objekte der wiederhergestellten Datenbank ansieht, kann den Namen ungewöhnlich finden.
- Die Wiederherstellung braucht die Erweiterung `dblink` auf dem Rechner des Eindringlings. Ohne sie meldet der Dump einen Fehler für die Erweiterung, und die Funktion läuft nicht.
