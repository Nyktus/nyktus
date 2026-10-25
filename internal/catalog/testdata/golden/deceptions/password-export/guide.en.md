# Password export of a browser

The file `Passwords.csv` has the columns that Chrome, Edge and other browsers write when the user exports saved passwords. Three entries belong to the account `j.doe`; the address of one of them is `https://t.example.net/portalq3xwz7a2kfm4ub6tyc5nre`. That URL belongs to a URL honeytoken: whoever opens the address, for example to try the password, raises an event and is redirected to the redirect target of the honeytoken. The passwords exist nowhere.

## Placing the file

1. Give the honeytoken a redirect target that fits the entry, such as the public login page of a service that you use.
2. Place the file where a user leaves an export that they should have deleted: in the downloads or documents of an account that exists only for this purpose, or on a share of the IT department.
3. Rename the entries if your own naming scheme differs from `wiki`, `build` and `portal`.
4. Record where you placed it in the placement notes of the artifact.

## Testing

Open the URL of the third entry in a browser on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only someone who opens the address raises an event. Reading the file does not.
- The first two entries point to names under `corp.example.com` that you do not control through Nyktus. Make sure that nobody enters these passwords anywhere, or that those names do not exist in your network.
- Whoever reads the file sees the URL, which names the address of your trigger and a random value.
