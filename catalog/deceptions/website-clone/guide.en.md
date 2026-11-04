# Script that detects a copy of your website

The file `site.js` is a script for the pages of your website `www.example.com`. If a browser loads a page that includes it from any other host, the script requests the invisible image `Honeytoken-URL`, which raises an event. On your own host it does nothing. That is what happens when someone copies your pages, including their scripts, to a server of their own to collect passwords from visitors.

## Placing the file

1. Upload the file to your web server, beside the other scripts, and include it in the pages that a copy would be made of, above all the login page: `<script src="/site.js"></script>`.
2. Rename it if your scripts follow another scheme, for example to `main.js`, and change the include to match.
3. If your pages are also served from other host names that you control, such as a test system, add those names to the list at the top of the script.
4. Record where you placed it in the notes of the scenario.

## Testing

Copy the login page with its scripts to another host, or open it from a local file, and load it in a browser. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- A copy that leaves out the scripts, or that removes this one, raises no event. Tools that copy pages as they are keep it.
- The script requests the image only when the host name differs. A test system or a preview that is not on the list raises events as well.
- The request shows the address of the page that loaded the script in its `Referer` header, if the browser sends it.
