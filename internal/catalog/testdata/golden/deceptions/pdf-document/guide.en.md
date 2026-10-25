# PDF document with a link and a lookup

This deception has no file to download: you write the PDF yourself, so that it fits where you place it, and add two things to it. A PDF cannot load a remote image while it is rendered, so there is no image to plant; the trigger is a link and an action.

## The link

Place a link over the whole first page. Whoever clicks anywhere on the page raises an event and is redirected to the redirect target of the honeytoken:

```
https://t.example.net/linkq3xwz7a2kfm4ub6tyc5nre
```

In Adobe Acrobat, LibreOffice Draw or another editor, use the tool for links, drag a rectangle over the whole page and choose "Open a web page" with this URL. Make the border invisible. In the file, the link is an annotation of the page:

```
<< /Type /Annot /Subtype /Link
   /Rect [0 0 595 842]
   /Border [0 0 0]
   /A << /S /URI /URI (https://t.example.net/linkq3xwz7a2kfm4ub6tyc5nre) >>
>>
```

## The action on opening

A second action starts when the document opens. It names this host, a DNS honeytoken:

```
hostq3xwz7a2kfm4ub6tyc5nre.d.example.net
```

In Acrobat, open the page properties, choose "Actions", trigger "Page Open" and the action "Open a web link" with the address `https://hostq3xwz7a2kfm4ub6tyc5nre.d.example.net/`. In the file, the action belongs to the catalog object of the document:

```
/OpenAction << /S /URI /URI (https://hostq3xwz7a2kfm4ub6tyc5nre.d.example.net/) >>
```

A tool such as `qpdf` or `mutool` shows and edits the objects.

## Writing the document

Give the document content that an intruder wants to read where you place it, such as an invoice, a draft of a contract or a network plan, and a name that fits. Place it where an intruder searches for valuable data, and record where you placed it in the notes of the scenario.

## Testing

Open the PDF on a computer with access to the internet and click on the page. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Readers differ. Many ask before they open a link from an action, and some resolve the host name before they ask, others do not. Treat the lookup as a bonus; the click on the link is the reliable trigger.
- A reader that blocks all connections of documents, or a viewer in the browser that ignores actions, raises no event.
- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- Whoever opens the PDF in an editor sees the URL and the host name.
