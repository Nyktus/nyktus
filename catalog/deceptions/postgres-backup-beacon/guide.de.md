## Geschichte

Binden Sie den Trigger an Ihre Sicherung selbst. Ein Angreifer, der einen Dump Ihrer Datenbank stiehlt, stellt ihn auf einem eigenen Rechner wieder her. Dort würde ein Wiederherstellungsskript, das nur auf Ihren Host zeigt, nie laufen. Beide Dateien sind SQL für Ihre Datenbank, mit einem DNS-Honeytoken als Host. Sie führen sie einmal aus, und jeder Dump, den Sie danach erzeugen, enthält die Objekte. Keine der Dateien legt eine Tabelle mit Daten an, und keine ändert Daten.

- `restore-hook.sql` legt die Funktion `refresh_catalog_stats` und die materialisierte Sicht `catalog_stats` an, die sie aufruft. Ein Dump enthält die Sicht ohne Inhalt und aktualisiert sie bei der Wiederherstellung, im Custom- und im Directory-Format ebenso wie in einem Klartext-Dump. Die Aktualisierung ruft die Funktion auf, und deren Verbindungsversuch mit `dblink` löst den Hostnamen auf, was ein Ereignis auslöst.
- `foreign-table.sql` legt eine Fremdtabelle `customer_payment_tokens` an, die auf eine entfernte Datenbank zeigt. Sie gehört zum Schema, übersteht jedes Dump-Format und löst den Hostnamen erst auf, wenn jemand die Tabelle abfragt, etwa auf der Suche nach Tabellen mit wertvollen Namen.

## Umsetzung

1. Legen Sie das DNS-Honeytoken „Datenbank-Host“ an. Ersetzen Sie `Honeytoken-Domain` in beiden Dateien durch seinen Namen.
2. Prüfen Sie, ob die Erweiterungen verfügbar sind: `dblink` für `restore-hook.sql` und `postgres_fdw` für `foreign-table.sql`. Sie gehören zu PostgreSQL, je nach Distribution im Paket `postgresql-contrib` oder im Server selbst.
3. Ersetzen Sie die Namen `refresh_catalog_stats`, `catalog_stats` und `customer_payment_tokens` durch Namen, die zu Ihrem Schema passen. Wählen Sie für die Tabelle einen Namen, den ein Angreifer lesen will. Die Namen stehen im Dump.
4. Führen Sie jede Datei in Ihrer Datenbank aus: `psql -d DATABASE -f restore-hook.sql` und `psql -d DATABASE -f foreign-table.sql`. Die Rolle braucht das Recht, eine Erweiterung und Objekte im Schema `public` anzulegen. Das Anlegen der Sicht führt die Funktion einmal aus, was einen Incident auslöst; schließen Sie ihn.
5. Verwenden Sie je Datenbank oder Sicherungssatz eine eigene Deception, damit ein Incident zeigt, welche Daten gestohlen wurden.
6. Notieren Sie im Szenario, welche Datenbank die Objekte enthält.

## Testen

Erzeugen Sie einen Dump mit `pg_dump DATABASE > dump.sql` und stellen Sie ihn auf einem Rechner mit Internetzugang in einer leeren Datenbank wieder her: `psql -d TEST -f dump.sql`. Innerhalb einer Minute zeigt das Szenario einen Incident. Fragen Sie dann die Fremdtabelle mit `SELECT * FROM customer_payment_tokens` ab, für einen zweiten Incident. Schließen Sie die Incidents nach dem Test.

Um nur die Namensauflösung zu prüfen, führen Sie `nslookup Honeytoken-Domain` mit dem Namen des Honeytokens aus.

## Grenzen

- Auch eine Testwiederherstellung Ihrer eigenen Datenbankadministratoren auf einem Rechner mit Internetzugang löst ein Ereignis aus; sagen Sie ihnen das.
- Eine Wiederherstellung in einem Netz, das keine Namen im Internet auflösen kann, erreicht die DNS-Rolle nicht. Das gilt für jedes Beacon in einer Sicherung: Es fängt den Angreifer, der Ihre Sicherung auf einem eigenen Rechner wiederherstellt, aber nicht den, der in einem abgeschotteten Labor arbeitet.
- Wer den Dump nach Hostnamen durchsucht oder sich die Objekte der wiederhergestellten Datenbank ansieht, kann den Namen ungewöhnlich finden.
- Die Wiederherstellung braucht die Erweiterung `dblink` auf dem Rechner des Angreifers. Ohne sie meldet der Dump einen Fehler für die Erweiterung, und die Funktion läuft nicht.
- Lassen Sie den Schemanamen `public.` vor `dblink_connect` in der Funktion stehen: Eine Wiederherstellung läuft mit leerem Suchpfad, und ohne den Namen scheitert die Funktion vor der Abfrage.
