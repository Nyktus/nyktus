# Browser bookmarks

The file `bookmarks.html` is an export of browser bookmarks in the format that every common browser writes and imports. In the bookmarks bar, a folder `Example Ltd` holds the link `VPN self\-service`, which leads to `https://t.example.net/portalq3xwz7a2kfm4ub6tyc5nre`. That URL belongs to a URL honeytoken: following the link raises an event and redirects the browser to the redirect target of the honeytoken.

## Placing the file

1. Give the honeytoken a redirect target that fits the name of the portal, such as the public login page of a service that you use.
2. Either place the file as an export, for example in the documents of an account that exists only for this purpose or in a backup of a user profile, or import it into the browser of such an account, so that the link appears in its bookmarks.
3. Add bookmarks of your own around it, such as the public sites of your organization, so that the file does not hold a single folder.
4. Record where you placed it in the placement notes of the artifact.

## Testing

Open the file in a browser and follow the link, or import it and open the bookmark. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Opening the file shows the bookmarks; only following the link raises an event.
- Whoever reads the file sees the URL, which names the address of your trigger and a random value.
