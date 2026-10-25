# Catalog of certificate templates

The file `Certificate-templates.html` is an internal page of the certification authority `Example Issuing CA 01`. It lists the usual certificate templates and links to the enrollment page `https://t.example.net/enrollmentq3xwz7a2kfm4ub6tyc5nre`. The file `Certificate-enrollment.html` holds the same link as a browser bookmark. The URL belongs to a URL honeytoken: whoever follows the link raises an event and is redirected to the redirect target of the honeytoken.

## Placing the file

1. Give the honeytoken a redirect target that fits the page, such as the public page of your organization.
2. Place the page where an intruder looks for ways to obtain certificates: on a file share of the IT department, next to the documentation of the public key infrastructure, or in the documents of an account that exists only for this purpose.
3. Import the bookmark file into the browser of such an account, or place it as an export, for example in a backup of the profile.
4. Record where you placed it in the placement notes of the artifact.

## Testing

Open the page in a browser on a computer with access to the internet and follow the link. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Opening the page or the bookmark file raises no event; only following the link does.
- The templates in the list are the ones that Windows certification authorities offer by default. If your authority has removed them, change the page to the templates it offers.
- Whoever reads the file sees the URL, which names the address of your trigger and a random value.
