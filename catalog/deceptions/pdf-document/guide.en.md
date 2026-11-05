## Story

Add a link and an action to a PDF that you write yourself. This deception has no file to download, so that the PDF fits where you place it. A PDF cannot load a remote image while it is rendered, so there is no image to plant; the trigger is a link and an action. Whoever clicks the link raises an event. The action starts when the document opens and names a DNS honeytoken, which raises an event when the reader looks the name up.

## Setup

1. Create the URL honeytoken "Link" and the DNS honeytoken "Host". The URL replaces `Honeytoken-URL` and the name replaces `Honeytoken-Domain` below.
2. Write the document. Give it content that an intruder wants to read, such as an invoice, a draft of a contract or a network plan, and a name that fits.
3. Place a link over the whole first page. Whoever clicks anywhere on the page is redirected to the redirect target of the honeytoken; give it a target that fits the document. The link opens this URL:

   ```
   Honeytoken-URL
   ```

   In Adobe Acrobat, LibreOffice Draw or another editor, use the tool for links, drag a rectangle over the whole page and choose `Open a web page` with this URL. Make the border invisible. In the file, the link is an annotation of the page:

   ```
   << /Type /Annot /Subtype /Link
      /Rect [0 0 595 842]
      /Border [0 0 0]
      /A << /S /URI /URI (Honeytoken-URL) >>
   >>
   ```

4. Add an action that starts when the document opens. It names this host:

   ```
   Honeytoken-Domain
   ```

   In Acrobat, open the page properties, choose `Actions`, the trigger `Page Open` and the action `Open a web link` with the address `https://Honeytoken-Domain/`. In the file, the action belongs to the catalog object of the document:

   ```
   /OpenAction << /S /URI /URI (https://Honeytoken-Domain/) >>
   ```

   A tool such as `qpdf` or `mutool` shows and edits the objects.
5. Place the PDF where an intruder searches for valuable data.
6. Record in the notes of the scenario where you placed the document.

## Testing

Open the PDF on a computer with access to the internet and click on the page. Within a minute, the scenario shows an incident. Close the incident after the test.

To check the honeytokens alone, run `curl Honeytoken-URL` and `nslookup Honeytoken-Domain`, with the URL and the name of the honeytokens.

## Limits

- Readers differ. Many ask before they open a link from an action, and some look up the host name before they ask, others do not. Treat the lookup as a bonus; the click on the link is the reliable trigger.
- A reader that blocks all connections of documents, or a viewer in the browser that ignores actions, raises no event.
- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- Whoever opens the PDF in an editor sees the URL and the host name.
- The labels of the editors are those of their English interface.
