# Interner Name, der auf einen Honeytoken zeigt

Ein Name in Ihrer internen DNS-Zone, `vault.corp.example.com`, zeigt mit einem CNAME-Eintrag auf den DNS-Honeytoken `targetq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Wer den Alias nachschlägt, weil er in einer Namensliste steht, ein Scan ihn findet oder er den Namen ausprobiert, lässt den internen Resolver den Honeytoken nachschlagen, was ein Event auslöst. Hinter dem Namen steht kein Dienst, und es gibt keine Datei abzulegen.

## Alias anlegen

1. Wählen Sie einen Namen, der zu einem Besuch einlädt, etwa `vault`, `backup01` oder `adminportal`, und tragen Sie ihn als Persona ein.
2. Legen Sie in der internen Zone `corp.example.com` einen CNAME-Eintrag von `vault` auf `targetq3xwz7a2kfm4ub6tyc5nre.d.example.net.` an, mit dem Punkt am Ende. Auf einem Windows-DNS-Server: `Add-DnsServerResourceRecordCName -Name 'vault' -HostNameAlias 'targetq3xwz7a2kfm4ub6tyc5nre.d.example.net.' -ZoneName 'corp.example.com'`. In einer BIND-Zonendatei: `vault IN CNAME targetq3xwz7a2kfm4ub6tyc5nre.d.example.net.`
3. Stellen Sie sicher, dass die internen Resolver Namen im Internet auflösen können. Sonst erreicht die Abfrage die DNS-Rolle von Nyktus nie.
4. Halten Sie den Alias in den Notizen des Szenarios fest.

## Testen

Führen Sie `nslookup vault.corp.example.com` auf einem Rechner aus, der den internen DNS-Server benutzt. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Resolver, der aus seinem Cache antwortet oder keine Namen im Internet auflösen kann, verhindert es.
- Wer die Zone auflistet oder eine Zonenübertragung anfordert, sieht den Alias und sein Ziel, ohne das Ziel nachzuschlagen. Das Ziel ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle, und ein Eindringling, der den Eintrag liest, kann es ungewöhnlich finden.
- Ein eigenes Werkzeug, das alle Namen der Zone auflöst, etwa ein Inventar oder ein Monitoring, löst ebenfalls ein Event aus. Nehmen Sie den Alias davon aus.
