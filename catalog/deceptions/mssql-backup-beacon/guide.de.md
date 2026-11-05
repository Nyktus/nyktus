## Geschichte

Binden Sie den Trigger an Ihre Sicherung selbst. Die Datei `procedure.sql` legt in Ihrer Datenbank eine gespeicherte Prozedur an. Läuft die Prozedur, listet sie ein Verzeichnis auf einer Freigabe auf, und dabei wird zuerst der Hostname der Freigabe aufgelöst. Der Hostname gehört zu einem DNS-Honeytoken. Jede `.bak`-Datei, die Sie danach erzeugen, enthält die Prozedur. Ein Angreifer, der eine Sicherung stiehlt und die Prozedur auf einer eigenen Instanz ausführt, löst also ein Ereignis aus. Die Prozedur liest nichts aus der Datenbank und ändert nichts.

## Umsetzung

1. Legen Sie das DNS-Honeytoken „Share-Host“ an. Ersetzen Sie `Honeytoken-Domain` in `procedure.sql` durch seinen Namen.
2. Benennen Sie die Prozedur `usp_ExportCustomerData` um, und zwar in einen Namen, den ein Angreifer ausführen will und der zu den Namen Ihrer Prozeduren passt.
3. Führen Sie die Datei in der Datenbank aus, deren Sicherungen Sie schützen wollen, zum Beispiel mit `sqlcmd -d DATABASE -i procedure.sql`. Die Anmeldung braucht das Recht, Prozeduren anzulegen.
4. Geben Sie niemandem das Recht, die Prozedur auszuführen, und rufen Sie sie selbst nur für den Test auf.
5. Verwenden Sie je Datenbank oder Sicherungssatz eine eigene Deception, damit ein Incident zeigt, welche Daten gestohlen wurden.
6. Notieren Sie im Szenario, welche Datenbank die Prozedur enthält.

## Testen

Sichern Sie die Datenbank, stellen Sie die Sicherung auf einer Instanz auf einem Rechner mit Internetzugang wieder her und führen Sie dort als Administrator dieser Instanz `EXEC [dbo].[usp_ExportCustomerData]` aus. Verwenden Sie den Namen, den Sie gewählt haben. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Um nur die Namensauflösung zu prüfen, führen Sie auf einem Rechner mit Internetzugang `nslookup Honeytoken-Domain` mit dem Namen des Honeytokens aus.

## Grenzen

- Das Wiederherstellen einer `.bak`-Datei führt keines der enthaltenen Objekte aus. Ein Ereignis entsteht erst, wenn jemand die Prozedur ausführt. Auch eine Testwiederherstellung Ihrer eigenen Datenbankadministratoren auf einem Rechner mit Internetzugang löst ein Ereignis aus; sagen Sie ihnen das.
- `xp_dirtree` steht den Administratoren einer Instanz zur Verfügung. Ein Angreifer, der Ihre Sicherung auf einer eigenen Instanz wiederherstellt, ist einer. Ist die erweiterte Prozedur abgeschaltet oder entfernt, scheitert die Prozedur vor der Abfrage.
- Eine Wiederherstellung in einem Netz, das keine Namen im Internet auflösen kann, erreicht die DNS-Rolle nicht. Das gilt für jedes Beacon in einer Sicherung: Es fängt den Angreifer, der Ihre Sicherung auf einem eigenen Rechner wiederherstellt, aber nicht den, der in einem abgeschotteten Labor arbeitet.
- Wer den Dump nach Hostnamen durchsucht oder sich die Objekte der wiederhergestellten Datenbank ansieht, kann den Namen ungewöhnlich finden.
