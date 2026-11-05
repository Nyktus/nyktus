## Story

Place addresses of internal portals where an intruder looks for them. Users and administrators note them in bookmarks, shortcuts, notes and exports. The files `bookmarks.html`, `SSO-reset.html`, `Portal.url` and `Passwords.csv` hold a URL that belongs to a URL honeytoken. Whoever follows the link raises an event and is redirected to the redirect target of the honeytoken. Nothing stands behind the addresses, and the accounts and passwords exist nowhere. One file is enough, and the files need not lie together. The files `Meeting-notes.md` and `Favorites.html` hold no honeytoken. They give the story a believable surrounding.

## Setup

Each placeholder in the files stands for one honeytoken:

- `Honeytoken-URL-Portal`: "Portal", in `bookmarks.html`, `SSO-reset.html` and `Passwords.csv`
- `Honeytoken-URL-Link`: "Link", in `Portal.url`

1. Create the two URL honeytokens.
2. Replace each placeholder with the URL of its honeytoken. Replace `Example Ltd` in the HTML and Markdown files with the name of your organization.
3. Give each honeytoken a redirect target that fits the name of the portal, such as the public login page of a service that you use. Whoever follows the link then sees a page.
4. Place the files where an intruder looks around, file by file.
5. `bookmarks.html`: as an export, for example in the documents of an account that exists only for this purpose or in a backup of a user profile, or import it into the browser of such an account, so that the link appears in its bookmarks. Add bookmarks of your own around it, so that the file does not hold a single folder.
6. `SSO-reset.html`: where an intruder looks for ways to take over accounts: on a file share of the IT department, in a folder with notes for the service desk or in the documents of an account that exists only for this purpose.
7. `Portal.url`: on the desktop or in the documents of such an account, on a file share of the IT department or in a folder with handover notes. Rename it so that its name promises something valuable, such as `VPN access.url`. The extension `.url` must stay.
8. `Passwords.csv`: where a user leaves an export that they should have deleted, such as the downloads or documents of such an account or a share of the IT department. Rename the entries if your naming scheme differs from `wiki`, `build` and `portal`.
9. `Meeting-notes.md` and `Favorites.html`: beside the other files of the story.
10. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `curl` with the URL of a honeytoken, such as `curl Honeytoken-URL-Portal`. The URLs are in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

Opening a file in a browser and following the link, or opening `Portal.url`, has the same effect.

## Limits

- Whoever reads one of the files, or looks at the properties of the shortcut, sees the URL. It names the address of your trigger and a random value.
- Only following the link raises an event. Opening `bookmarks.html` or `SSO-reset.html`, reading `Passwords.csv` and listing the folder of `Portal.url` in the Windows Explorer raise none.
- The first two entries of `Passwords.csv` point to names under `corp.example.com` that you do not control through Nyktus. Make sure that nobody enters these passwords anywhere, or that those names do not exist in your network.
