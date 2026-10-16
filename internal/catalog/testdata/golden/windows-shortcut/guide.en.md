# Internet shortcut

The file `Portal.url` is a Windows shortcut to the URL `https://t.example.net/linkq3xwz7a2kfm4ub6tyc5nre`. That URL belongs to a URL honeytoken: opening the shortcut opens it in the browser, which raises an event, and the browser is redirected to the redirect target of the honeytoken, or to the default target of the trigger.

## Placing the file

1. Give the honeytoken a redirect target that fits the name of the shortcut, such as the public login page of a service that you use. Whoever opens the shortcut sees that page.
2. Rename the file so that its name promises something valuable, such as `VPN access.url`, `Payroll.url` or `Admin console.url`. The extension `.url` must stay.
3. Place it where an intruder looks around, such as the desktop or the documents of an account that exists only for this purpose, a file share of the IT department or a folder with handover notes.
4. Record where you placed it in the placement notes of the artifact.

## Testing

Open the shortcut on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- The shortcut raises an event only when someone opens it. Windows Explorer does not request the URL when it lists the folder.
- Whoever looks at the properties of the shortcut, or opens it in a text editor, sees the URL. It names the address of your trigger and a random value.
