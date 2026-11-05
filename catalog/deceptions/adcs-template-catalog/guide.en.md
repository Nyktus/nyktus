## Story

Place the page of a certification authority where an intruder looks for ways to obtain certificates. The file `Certificate-templates.html` is an internal page of the authority `Example Issuing CA 01`. It lists the usual certificate templates and links to an enrollment page. The file `Certificate-enrollment.html` holds the same link as a browser bookmark. The URL of the link belongs to a URL honeytoken: whoever follows the link raises an event and is redirected to the redirect target of the honeytoken.

## Setup

1. Create the URL honeytoken "Enrollment page". Replace `Honeytoken-URL` in both files with its URL. Give the honeytoken a redirect target that fits the page, such as the public page of your organization.
2. Replace the name `Example Issuing CA 01` with a name that fits your environment. If your authority has removed the default templates of Windows from the list, change the list to the templates it offers.
3. Place the page where an intruder looks for ways to obtain certificates: on a file share of the IT department, next to the documentation of the public key infrastructure, or in the documents of an account that exists only for this purpose.
4. Import the bookmark file into the browser of such an account, or place it as an export, for example in a backup of the profile.
5. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `curl Honeytoken-URL`, with the URL of the honeytoken instead of the placeholder. The URL is in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

If no incident appears, check that the computer reaches the address of the trigger of Nyktus.

## Limits

- Opening the page or the bookmark file raises no event; only following the link does.
- Whoever reads the file sees the URL, which names the address of your trigger and a random value.
