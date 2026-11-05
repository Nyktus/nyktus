## Geschichte

Legen Sie die Konfiguration eines MCP-Clients dort ab, wo Entwickler ihre Werkzeuge halten. Entwickler verbinden KI-Assistenten über das Model Context Protocol mit internen Servern, und die Konfiguration enthält die Adresse und den Schlüssel des Servers. Die Datei `mcp.json` konfiguriert einen Server namens `knowledge-base`, der über HTTP erreicht wird, mit einem Header `Authorization` und einem zufälligen Token. Der Hostname des Servers gehört zu einem DNS-Honeytoken: Ein Client, der sich mit dem Server verbindet, löst den Namen auf, und das löst ein Ereignis aus. Hinter dem Namen steht kein Server, und das Token gibt es nirgends.

## Umsetzung

1. Legen Sie das DNS-Honeytoken „MCP-Server“ an. Ersetzen Sie `Honeytoken-Domain` in der Datei durch seinen Namen.
2. Legen Sie die Datei als `.mcp.json` im Hauptverzeichnis eines Projektverzeichnisses ab, das Entwickler nutzen, oder als `mcp.json` im Konfigurationsverzeichnis des KI-Assistenten, den Sie vortäuschen.
3. Legen Sie sie nicht in einem Projekt ab, das jemand mit einem Assistenten öffnet. Der Client würde um Freigabe des Servers bitten, und eine Freigabe ließe ihn die Verbindung aufbauen.
4. Notieren Sie im Szenario, wo die Datei liegt.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup Honeytoken-Domain` mit dem Namen des Honeytokens aus, oder `curl https://Honeytoken-Domain/mcp`. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Erscheint kein Incident, prüfen Sie, ob der Rechner Namen über einen Resolver auflöst, der die DNS-Rolle von Nyktus erreicht (siehe „Grenzen“).

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Clients fragen nach, bevor sie sich mit einem Server aus der Konfiguration eines Projekts verbinden. Die Datei löst ein Ereignis nur aus, wo jemand den Server freigegeben hat oder die URL verwendet. Das bloße Lesen der Datei löst keines aus.
- Der Hostname ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Wer die Datei genau liest, kann ihn ungewöhnlich finden.
