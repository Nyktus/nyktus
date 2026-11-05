## Story

Place a script in your website that detects a copy of it. The file `site.js` is a script for the pages of your website. If a browser loads a page that includes it from any other host, the script requests an invisible image, which raises an event. On your own host it does nothing. That is what happens when someone copies your pages, including their scripts, to a server of their own to collect passwords from visitors.

## Setup

1. Create the image honeytoken "Image". Replace `Honeytoken-URL` in `site.js` with its URL.
2. Replace `www.example.com` at the top of the script with the host name of your website. If your pages are also served from other host names that you control, such as a test system, add those names to the same condition.
3. Upload the file to your web server, beside the other scripts, and include it in the pages that a copy would be made of, above all the login page: `<script src="/site.js"></script>`.
4. If your scripts follow another naming scheme, rename the file, for example to `main.js`, and change the include to match.
5. Record in the notes of the scenario where you placed the file.

## Testing

Copy the login page with its scripts to another host, or open it from a local file, and load it in a browser. Within a minute, the scenario shows an incident. Close the incident after the test.

To check only the honeytoken, run `curl Honeytoken-URL`, with the URL of the honeytoken, on a computer with access to the internet.

## Limits

- A copy that leaves out the scripts, or that removes this one, raises no event. Tools that copy pages as they are keep it.
- The script requests the image only when the host name differs. A test system or a preview that is not on the list raises events as well.
- The request shows the address of the page that loaded the script in its `Referer` header, if the browser sends it.
