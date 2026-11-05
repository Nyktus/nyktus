## Geschichte

Bringen Sie QR-Code-Etiketten an Geräten im Serverraum an. Diese Deception hat keine Datei zum Herunterladen: Sie verlangt drei URL-Honeytokens, die Sie als QR-Codes drucken und an Geräten anbringen, wie es bei Inventaretiketten oft üblich ist. Wer einen Code scannt, öffnet die URL im Browser seines Telefons, was ein Ereignis auslöst und den Browser auf das Weiterleitungsziel des Honeytokens umleitet. Das Ereignis zeigt die Adresse des Telefons, oft ein Mobilfunknetz oder das Gästenetz, und einen mobilen Browser. In einem Serverraum ist beides ungewöhnlich.

## Umsetzung

Ein Platzhalter benennt die URL jedes Honeytokens:

- `Honeytoken-URL-Rack`: „Rack-Etikett“
- `Honeytoken-URL-Device`: „Geräte-Etikett“
- `Honeytoken-URL-PatchPanel`: „Patchfeld-Etikett“

1. Legen Sie die drei URL-Honeytokens an.
2. Geben Sie jedem Honeytoken ein Weiterleitungsziel, das zu seiner Beschriftung passt, etwa die öffentliche Seite des Herstellers oder Ihrer Organisation. Wer den Code scannt, sieht dann eine Seite und bemerkt keine Falle.
3. Öffnen Sie jedes Honeytoken in der Console. Es zeigt den QR-Code seiner URL, den Sie drucken können. Drucken Sie jeden Code auf ein Etikett mit einer Beschriftung, die dorthin passt, wo es hinkommt, so wie die Inventaretiketten in Ihrem Raum aussehen: für das Rack die Inventarnummer und den Text „Dokumentation“, für das Gerät „Wartung und Garantie“, für das Patchfeld „Portplan“.
4. Bringen Sie die Etiketten dort an, wo ein Angreifer im Raum hinsieht: am Rahmen oder an der Innenseite der Tür des Racks für das erste, an der Innenseite der Abdeckung eines Geräts oder an einem Laufwerksschacht für das zweite, an der Vorderseite des Patchfelds oder an der Tür des Netzwerkschranks für das dritte. Bringen Sie sie zusätzlich zu Ihren echten Etiketten an, nicht statt dieser.
5. Verwenden Sie für jedes Rack, jedes Gerät und jeden Schrank ein eigenes Honeytoken. Der Incident zeigt dann, wo die Person stand. Notieren Sie in den Platzierungsnotizen des Honeytokens, wo Sie jedes Etikett angebracht haben.
6. Sagen Sie den Menschen, die im Raum arbeiten, Bescheid. Auch wer ein Etikett aus Neugier scannt, löst ein Ereignis aus.

## Testen

Scannen Sie jeden Code mit einem Telefon. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie die Incidents nach dem Test.

Um eine URL ohne Telefon zu prüfen, führen Sie auf einem Rechner mit Internetzugang `curl Honeytoken-URL-Rack` mit der URL des Honeytokens statt des Platzhalters aus.

## Grenzen

- Ein Ereignis entsteht nur, wenn jemand den Code scannt. Wer das Etikett nur ansieht oder fotografiert, löst keines aus.
- Die URL zeigt die Adresse Ihres Triggers und einen Zufallswert. Wer den Code mit einem Scanner liest, der die Adresse anzeigt, sieht sie.
- Ein Telefon, das über ein VPN der Organisation scannt, zeigt dessen Adresse und kein Mobilfunknetz.
