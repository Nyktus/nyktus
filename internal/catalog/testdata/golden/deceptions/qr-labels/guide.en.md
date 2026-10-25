# QR code labels in the server room

This deception has no file to download: it gives you three URLs, which you print as QR codes and attach to equipment, as asset labels often are. Whoever scans a code opens the URL in the browser of their phone, which raises an event and redirects the browser to the redirect target of the honeytoken. The event shows the address of the phone, often a mobile network or the guest network, and a mobile browser. In a server room, both are unusual.

- Rack: `https://t.example.net/rackq3xwz7a2kfm4ub6tyc5nre`
- Device: `https://t.example.net/deviceq3xwz7a2kfm4ub6tyc5nre`
- Patch panel: `https://t.example.net/patchpanelq3xwz7a2kfm4ub6tyc5nre`

## Placing the labels

1. Open each honeytoken in the console. It shows the QR code of its URL, which you can print. Print each code on a label with a caption that fits where it goes, as the asset labels in your room look: for the rack, the asset number and the text "Documentation"; for the device, "Service and warranty"; for the patch panel, "Port plan".
2. Attach the labels where an intruder in the room looks: the frame or inside of the door of the rack for the first, the inside of the cover of a device or a drive tray for the second, the front of the patch panel or the door of the network cabinet for the third.
3. Attach them in addition to your real labels, not instead of them.
4. Give each honeytoken a redirect target that fits its caption, such as the public page of the manufacturer or of your organization. Whoever scans the code then sees a page and does not notice a trap.
5. Use a honeytoken of its own for each rack, device or cabinet. The incident then tells you where the person stood. Record where you attached each label in the placement notes of the honeytoken.
6. Tell the people who work in the room. Whoever scans a label out of curiosity raises an event as well.

## Testing

Scan each code with a phone. Within a minute, the scenario shows an incident. Close the incidents after the test.

## Limits

- An event happens only when somebody scans the code. A person who only looks at the label, or photographs it, raises none.
- The URL shows the address of your trigger and a random value. Whoever reads the code with a scanner that shows the address sees it.
- A phone that scans over a VPN of the organization shows its address, not a mobile network.
