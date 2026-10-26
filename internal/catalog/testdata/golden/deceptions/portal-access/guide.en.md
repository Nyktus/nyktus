# Access to internal portals

Users and administrators note the addresses of internal portals in bookmarks, shortcuts, notes and exports. The files below hold such addresses. The files share the honeytokens of the story, so the same address appears in every file that names the same portal. Nothing stands behind the addresses: the accounts and passwords exist nowhere. You decide which files you place and where; one is enough, and they need not lie together.

## Browser bookmarks

The file `bookmarks.html` is an export of browser bookmarks in the format that every common browser writes and imports. In the bookmarks bar, a folder `Example Ltd` holds the link `VPN self\-service`, which leads to `https://t.example.net/portalq3xwz7a2kfm4ub6tyc5nre`. That URL belongs to a URL honeytoken: following the link raises an event and redirects the browser to the redirect target of the honeytoken.

### Placing the file

1. Give the honeytoken a redirect target that fits the name of the portal, such as the public login page of a service that you use.
2. Either place the file as an export, for example in the documents of an account that exists only for this purpose or in a backup of a user profile, or import it into the browser of such an account, so that the link appears in its bookmarks.
3. Add bookmarks of your own around it, such as the public sites of your organization, so that the file does not hold a single folder.
4. Record where you placed it in the placement notes of the artifact.

### Testing

Open the file in a browser and follow the link, or import it and open the bookmark. Within a minute, the scenario shows an incident. Close the incident after the test.

## Note on the reset of single sign-on

The file `SSO-reset.html` is a short note of the IT department of `Example Ltd` with a link to a portal for resetting the single sign-on: `https://t.example.net/portalq3xwz7a2kfm4ub6tyc5nre`. The URL belongs to a URL honeytoken: whoever follows the link raises an event and is redirected to the redirect target of the honeytoken.

### Placing the file

1. Give the honeytoken a redirect target that fits the portal, such as the public login page of a service that you use.
2. Place the file where an intruder looks for ways to take over accounts: on a file share of the IT department, in a folder with notes for the service desk, in the documents of an account that exists only for this purpose.
3. Change `Contact` to a team that exists.
4. Record where you placed it in the placement notes of the artifact.

### Testing

Open the file in a browser on a computer with access to the internet and follow the link. Within a minute, the scenario shows an incident. Close the incident after the test.

## Internet shortcut

The file `Portal.url` is a Windows shortcut to the URL `https://t.example.net/linkq3xwz7a2kfm4ub6tyc5nre`. That URL belongs to a URL honeytoken: opening the shortcut opens it in the browser, which raises an event, and the browser is redirected to the redirect target of the honeytoken, or to the default target of the trigger.

### Placing the file

1. Give the honeytoken a redirect target that fits the name of the shortcut, such as the public login page of a service that you use. Whoever opens the shortcut sees that page.
2. Rename the file so that its name promises something valuable, such as `VPN access.url`, `Payroll.url` or `Admin console.url`. The extension `.url` must stay.
3. Place it where an intruder looks around, such as the desktop or the documents of an account that exists only for this purpose, a file share of the IT department or a folder with handover notes.
4. Record where you placed it in the placement notes of the artifact.

### Testing

Open the shortcut on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Password export of a browser

The file `Passwords.csv` has the columns that Chrome, Edge and other browsers write when the user exports saved passwords. Three entries belong to the account `j.doe`; the address of one of them is `https://t.example.net/portalq3xwz7a2kfm4ub6tyc5nre`. That URL belongs to a URL honeytoken: whoever opens the address, for example to try the password, raises an event and is redirected to the redirect target of the honeytoken. The passwords exist nowhere.

### Placing the file

1. Give the honeytoken a redirect target that fits the entry, such as the public login page of a service that you use.
2. Place the file where a user leaves an export that they should have deleted: in the downloads or documents of an account that exists only for this purpose, or on a share of the IT department.
3. Rename the entries if your own naming scheme differs from `wiki`, `build` and `portal`.
4. Record where you placed it in the placement notes of the artifact.

### Testing

Open the URL of the third entry in a browser on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Whoever reads one of the files, or looks at the properties of the shortcut, sees the URL. It names the address of your trigger and a random value.
- `bookmarks.html`: Opening the file shows the bookmarks; only following the link raises an event.
- `SSO-reset.html`: Opening the file raises no event; only following the link does.
- `Portal.url`: The shortcut raises an event only when someone opens it. Windows Explorer does not request the URL when it lists the folder.
- `Passwords.csv`: Only someone who opens the address raises an event. Reading the file does not.
- `Passwords.csv`: The first two entries point to names under `corp.example.com` that you do not control through Nyktus. Make sure that nobody enters these passwords anywhere, or that those names do not exist in your network.
