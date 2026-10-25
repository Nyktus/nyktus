# QR-Code-Etiketten im Serverraum

Diese Deception hat keine Datei zum Herunterladen: Sie gibt Ihnen drei URLs, die Sie als QR-Codes drucken und an Geräten anbringen, wie es Inventaretiketten oft sind. Wer einen Code scannt, öffnet die URL im Browser seines Telefons, was ein Event auslöst und den Browser auf das Weiterleitungsziel des Honeytokens weiterleitet. Das Event zeigt die Adresse des Telefons, oft ein Mobilfunknetz oder das Gastnetz, und einen mobilen Browser. In einem Serverraum ist beides ungewöhnlich.

- Rack: `https://t.example.net/rackq3xwz7a2kfm4ub6tyc5nre`
- Gerät: `https://t.example.net/deviceq3xwz7a2kfm4ub6tyc5nre`
- Patchfeld: `https://t.example.net/patchpanelq3xwz7a2kfm4ub6tyc5nre`

## Etiketten anbringen

1. Öffnen Sie jeden Honeytoken in der Console. Sie zeigt den QR-Code seiner URL, den Sie drucken können. Drucken Sie jeden Code auf ein Etikett mit einer Aufschrift, die dazu passt, wo er hingehört, wie die Inventaretiketten in Ihrem Raum aussehen: für das Rack die Inventarnummer und den Text „Dokumentation“, für das Gerät „Service und Garantie“, für das Patchfeld „Portbelegung“.
2. Bringen Sie die Etiketten dort an, wo ein Eindringling im Raum hinsieht: am Rahmen oder an der Innenseite der Tür des Racks für das erste, an der Innenseite des Gehäusedeckels oder an einem Laufwerksträger für das zweite, an der Front des Patchfelds oder an der Tür des Netzwerkschranks für das dritte.
3. Bringen Sie sie zusätzlich zu Ihren echten Etiketten an, nicht statt ihrer.
4. Geben Sie jedem Honeytoken ein Weiterleitungsziel, das zur Aufschrift passt, etwa die öffentliche Seite des Herstellers oder Ihrer Organisation. Wer den Code scannt, sieht dann eine Seite und bemerkt keine Falle.
5. Verwenden Sie für jedes Rack, jedes Gerät und jeden Schrank einen eigenen Honeytoken. Der Incident zeigt Ihnen dann, wo die Person stand. Halten Sie in den Platzierungsnotizen des Honeytokens fest, wo Sie jedes Etikett angebracht haben.
6. Informieren Sie die Menschen, die im Raum arbeiten. Wer ein Etikett aus Neugier scannt, löst ebenfalls ein Event aus.

## Testen

Scannen Sie jeden Code mit einem Telefon. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie die Incidents nach dem Test.

## Grenzen

- Ein Event entsteht nur, wenn jemand den Code scannt. Wer das Etikett nur ansieht oder fotografiert, löst keines aus.
- Die URL zeigt die Adresse Ihres Triggers und einen Zufallswert. Wer den Code mit einem Scanner liest, der die Adresse anzeigt, sieht sie.
- Ein Telefon, das über ein VPN der Organisation scannt, zeigt dessen Adresse, nicht ein Mobilfunknetz.
