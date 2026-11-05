## Geschichte

Legen Sie Adressen interner Portale dort ab, wo ein Angreifer sie sucht. Benutzer und Administratoren notieren sie in Lesezeichen, Verknüpfungen, Notizen und Exporten. Die Dateien `bookmarks.html`, `SSO-reset.html`, `Portal.url` und `Passwords.csv` enthalten eine URL, die zu einem URL-Honeytoken gehört. Wer dem Link folgt, löst ein Ereignis aus und wird auf das Weiterleitungsziel des Honeytokens umgeleitet. Hinter den Adressen steht nichts, und Konten und Passwörter gibt es nirgends. Eine Datei genügt, und die Dateien müssen nicht beieinander liegen. Die Dateien `Meeting-notes.md` und `Favorites.html` enthalten keinen Honeytoken. Sie geben der Geschichte eine glaubhafte Umgebung.

## Umsetzung

Jeder Platzhalter in den Dateien gehört zu einem Honeytoken:

- `Honeytoken-URL-Portal`: „Portal“, in `bookmarks.html`, `SSO-reset.html` und `Passwords.csv`
- `Honeytoken-URL-Link`: „Link“, in `Portal.url`

1. Legen Sie die zwei URL-Honeytokens an.
2. Ersetzen Sie jeden Platzhalter durch die URL seines Honeytokens. Ersetzen Sie `Example Ltd` in den HTML- und Markdown-Dateien durch den Namen Ihrer Organisation.
3. Geben Sie jedem Honeytoken ein Weiterleitungsziel, das zum Namen des Portals passt, etwa die öffentliche Anmeldeseite eines Dienstes, den Sie nutzen. Wer dem Link folgt, sieht dann eine Seite.
4. Legen Sie die Dateien dort ab, wo ein Angreifer sich umsieht, Datei für Datei.
5. `bookmarks.html`: als Export, etwa in den Dokumenten eines Kontos, das nur diesem Zweck dient, oder in einer Sicherung eines Benutzerprofils. Oder importieren Sie sie in den Browser eines solchen Kontos, damit der Link in dessen Lesezeichen erscheint. Fügen Sie eigene Lesezeichen hinzu, damit die Datei nicht nur einen einzigen Ordner enthält.
6. `SSO-reset.html`: dort, wo ein Angreifer nach Wegen sucht, Konten zu übernehmen: auf einer Dateifreigabe der IT, in einem Ordner mit Notizen für den Service Desk oder in den Dokumenten eines Kontos, das nur diesem Zweck dient.
7. `Portal.url`: auf dem Desktop oder in den Dokumenten eines solchen Kontos, auf einer Dateifreigabe der IT oder in einem Ordner mit Übergabenotizen. Benennen Sie sie so um, dass der Name etwas Wertvolles verspricht, etwa `VPN access.url`. Die Endung `.url` muss bleiben.
8. `Passwords.csv`: dort, wo ein Benutzer einen Export liegen lässt, den er hätte löschen sollen, etwa in den Downloads oder Dokumenten eines solchen Kontos oder auf einer Freigabe der IT. Ändern Sie die Einträge, wenn Ihr Namensschema von `wiki`, `build` und `portal` abweicht.
9. `Meeting-notes.md` und `Favorites.html`: neben den anderen Dateien der Geschichte.
10. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `curl` mit der URL eines Honeytokens aus, zum Beispiel `curl Honeytoken-URL-Portal`. Die URLs stehen in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Dasselbe bewirkt es, eine Datei im Browser zu öffnen und dem Link zu folgen oder `Portal.url` zu öffnen.

## Grenzen

- Wer eine der Dateien liest oder sich die Eigenschaften der Verknüpfung ansieht, sieht die URL. Sie nennt die Adresse Ihres Triggers und einen Zufallswert.
- Nur das Folgen des Links löst ein Ereignis aus. Das Öffnen von `bookmarks.html` oder `SSO-reset.html`, das Lesen von `Passwords.csv` und das Auflisten des Ordners von `Portal.url` im Windows-Explorer lösen keines aus.
- Die ersten zwei Einträge in `Passwords.csv` zeigen auf Namen unter `corp.example.com`, die Sie nicht über Nyktus steuern. Stellen Sie sicher, dass niemand diese Passwörter irgendwo eingibt, oder dass es diese Namen in Ihrem Netz nicht gibt.
