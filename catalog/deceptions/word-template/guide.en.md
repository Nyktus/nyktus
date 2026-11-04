# Word document with a template on a remote host

This deception has no file to download: you write the document yourself, so that it fits where you place it, and attach a template to it that lies on this host:

```
Honeytoken-Domain
```

The name belongs to a DNS honeytoken. Word reads the attached template of a document when it opens it. If the template lies on a remote host, Word resolves the host name first, which raises an event. The lookup happens even when the connection to the host fails afterwards or the network blocks it.

## Writing the document

Give the document content that an intruder wants to read where you place it, such as a list of servers, a network plan or notes on a project. A document with a single empty page stands out. Save it as `.docx`.

## Attaching the template

1. Rename the file to `.zip` and unpack it.
2. In `word/settings.xml`, add this element directly before the element `<w:defaultTabStop`. Word is strict about the order of the elements in this file:

   ```
   <w:attachedTemplate r:id="rId1"/>
   ```

3. Create the file `word/_rels/settings.xml.rels` with this content, or, if it exists, add the `Relationship` to it:

   ```
   <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
   <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
     <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///\\Honeytoken-Domain\templates\normal.dotx" TargetMode="External"/>
   </Relationships>
   ```

4. Pack the files again, with `[Content_Types].xml` first, and rename the file back to `.docx`.

## Placing the document

Place it where an intruder searches for valuable data, such as a file share of the finance or personnel department, a document management system or a backup. Record where you placed it in the notes of the scenario.

## Testing

Open the document in Word on a computer with access to the internet and enable editing. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Word opens documents from the internet and from some network shares in Protected View, which loads no remote template. Only "Enable Editing" starts the lookup.
- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- Other programs, such as LibreOffice or a viewer in the browser, do not load the template.
- The host name is a random label under the zone of your DNS role. An intruder who unpacks the document can find it unusual.
