## Story

Place a saved e-mail where an intruder searches for mail. The file `message.html` is an e-mail as HTML, as a mail client saves or exports it. It has the subject `Mailbox storage almost full`, a link with the text `Open mailbox overview` and an invisible image of one pixel. Both URLs belong to honeytokens: following the link raises an event and redirects the browser to the redirect target of the honeytoken, and loading the image raises an event as well.

## Setup

Each placeholder in the file stands for one honeytoken:

- `Honeytoken-URL-Link`: "Link", the link `Open mailbox overview`
- `Honeytoken-URL-Pixel`: "Image", the invisible image

1. Create the two URL honeytokens. Replace each placeholder in the file with the URL of its honeytoken.
2. Give the honeytoken "Link" a redirect target that fits the text of the link, such as the public login page of a service that you use.
3. Place the file where an intruder searches for mail: in an export of a mailbox, in a folder of saved messages in the documents of an account that exists only for this purpose, or on a share with mail backups.
4. Name it like the exports in that place, for example after the subject.
5. Record in the notes of the scenario where you placed the file.

## Testing

On a computer with access to the internet, run `curl Honeytoken-URL-Link` and `curl Honeytoken-URL-Pixel`, with the URL of each honeytoken instead of the placeholder. The URLs are in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

If no incident appears, check that the computer reaches the address of the trigger of Nyktus.

## Limits

- Opening the file in a browser raises an event by itself, because the browser loads the image. Opening it in an editor does not.
- Mail gateways and previews can load the image and the link without anyone reading the message. Do not send the file by mail.
- Whoever reads the file sees the URLs, which name the address of your trigger and a random value.
