## Geschichte

Tragen Sie in Ihre interne DNS-Zone einen Namen ein, der auf ein DNS-Honeytoken zeigt. Der Name `vault.corp.example.com` ist ein CNAME-Eintrag, der auf das Honeytoken zeigt. Wer den Alias auflöst, lässt den internen Resolver das Honeytoken auflösen, und das löst ein Ereignis aus. Das geschieht, wenn der Alias in einer Namensliste steht, wenn ein Scan ihn findet oder wenn jemand den Namen ausprobiert. Hinter dem Namen steht kein Dienst, und es gibt keine Datei, die Sie ablegen.

## Umsetzung

1. Legen Sie das DNS-Honeytoken „Ziel des Alias“ an.
2. Wählen Sie einen Namen, der zu einem Besuch einlädt, etwa `vault`, `backup01` oder `adminportal`. Die folgenden Schritte verwenden `vault`.
3. Legen Sie in der internen Zone `corp.example.com` einen CNAME-Eintrag von `vault` auf `Honeytoken-Domain.` an, mit dem Punkt am Ende, und ersetzen Sie `Honeytoken-Domain` durch den Namen des Honeytokens. Auf einem Windows-DNS-Server: `Add-DnsServerResourceRecordCName -Name 'vault' -HostNameAlias 'Honeytoken-Domain.' -ZoneName 'corp.example.com'`. In einer BIND-Zonendatei: `vault IN CNAME Honeytoken-Domain.`
4. Wenn die internen Resolver keine Namen im Internet auflösen können, richten Sie das ein. Sonst erreicht die Abfrage die DNS-Rolle von Nyktus nie.
5. Notieren Sie den Alias im Szenario.

## Testen

Führen Sie `nslookup vault.corp.example.com` auf einem Rechner aus, der den internen DNS-Server nutzt. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Erscheint kein Incident, führen Sie `nslookup Honeytoken-Domain` mit dem Namen des Honeytokens aus. So prüfen Sie, ob der Resolver die DNS-Rolle von Nyktus erreicht.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Resolver, der aus seinem Cache antwortet oder keine Namen im Internet auflösen kann, verhindert das.
- Wer die Zone auflistet oder einen Zonentransfer anfordert, sieht den Alias und sein Ziel, ohne das Ziel abzufragen. Das Ziel ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle, und ein Angreifer, der den Eintrag liest, kann es ungewöhnlich finden.
- Ein eigenes Werkzeug, das alle Namen der Zone auflöst, etwa eine Bestandsaufnahme oder ein Monitoring, löst ebenfalls ein Ereignis aus. Nehmen Sie den Alias davon aus.
