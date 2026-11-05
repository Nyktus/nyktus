## Story

Attach a template on a remote host to a Word document that you write yourself. This deception has no file to download, so that the document fits where you place it. The name of the host belongs to a DNS honeytoken. Word reads the attached template of a document when it opens it. If the template lies on a remote host, Word looks up the host name first, which raises an event. The lookup happens even when the connection to the host fails afterwards or the network blocks it.

## Setup

1. Create the DNS honeytoken "Host". Its name replaces `Honeytoken-Domain` below.
2. Write the document. Give it content that an intruder wants to read where you place it, such as a list of servers, a network plan or notes on a project. A document with a single empty page stands out. Save it as `.docx`.
3. Rename the file to `.zip` and unpack it.
4. In `word/settings.xml`, add this element directly before the element `<w:defaultTabStop`. Word is strict about the order of the elements in this file:

   ```
   <w:attachedTemplate r:id="rId1"/>
   ```

5. Create the file `word/_rels/settings.xml.rels` with this content, or, if it exists, add the `Relationship` to it. Use the name of the honeytoken instead of the placeholder:

   ```
   <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
   <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
     <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///\\Honeytoken-Domain\templates\normal.dotx" TargetMode="External"/>
   </Relationships>
   ```

6. Pack the files again, with `[Content_Types].xml` first, and rename the file back to `.docx`.
7. Place the document where an intruder searches for valuable data, such as a file share of the finance or personnel department, a document management system or a backup.
8. Record in the notes of the scenario where you placed the document.

## Testing

Open the document in Word on a computer with access to the internet and click `Enable Editing`. Within a minute, the scenario shows an incident. Close the incident after the test.

To check only the name resolution, run `nslookup Honeytoken-Domain`, with the name of the honeytoken.

## Limits

- Word opens documents from the internet and from some network shares in `Protected View`, which loads no remote template. Only `Enable Editing` starts the lookup.
- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- Other programs, such as LibreOffice or a viewer in the browser, do not load the template.
- The host name is a random label under the zone of your DNS role. An intruder who unpacks the document can find it unusual.
