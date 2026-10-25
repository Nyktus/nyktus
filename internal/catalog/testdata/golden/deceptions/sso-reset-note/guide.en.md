# Note on the reset of single sign-on

The file `SSO-reset.html` is a short note of the IT department of `Example Corp` with a link to a portal for resetting the single sign-on: `https://t.example.net/portalq3xwz7a2kfm4ub6tyc5nre`. The URL belongs to a URL honeytoken: whoever follows the link raises an event and is redirected to the redirect target of the honeytoken.

## Placing the file

1. Give the honeytoken a redirect target that fits the portal, such as the public login page of a service that you use.
2. Place the file where an intruder looks for ways to take over accounts: on a file share of the IT department, in a folder with notes for the service desk, in the documents of an account that exists only for this purpose.
3. Change `Contact` to a team that exists.
4. Record where you placed it in the placement notes of the artifact.

## Testing

Open the file in a browser on a computer with access to the internet and follow the link. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Opening the file raises no event; only following the link does.
- Whoever reads the file sees the URL, which names the address of your trigger and a random value.
