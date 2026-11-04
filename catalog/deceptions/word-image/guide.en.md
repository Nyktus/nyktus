# Linked image in a Word document

This deception has no file to download: you write the document yourself, so that it fits where you place it, and link this image in it:

```
Honeytoken-URL
```

The URL belongs to an image honeytoken. It always answers with an invisible image of one pixel. Word loads a linked image from its URL whenever it opens the document, and the request raises an event.

## Writing the document

Give the document content that an intruder wants to read where you place it, such as salary figures, a list of contacts for emergencies or the plan of a project. A document that holds nothing but an image stands out.

## Linking the image

1. Place the cursor at an inconspicuous spot, for example at the end of the document.
2. Press `Ctrl+F9`. Word inserts an empty field `{ }`.
3. Write between the braces:

   ```
   INCLUDEPICTURE "Honeytoken-URL" \d
   ```

   `\d` keeps Word from storing the image in the document, so that it loads it again with every opening.
4. Press `F9` to update the field, and save the document as `.docx`.

## Placing the document

Place it where an intruder searches for valuable data, such as a file share of the finance or personnel department, a document management system or a backup. Record where you placed it in the notes of the scenario.

## Testing

Open the document in Word on a computer with access to the internet and enable editing. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Word opens documents from the internet and from some network shares in Protected View, which loads no images. Only "Enable Editing" sends the request.
- Mail gateways and previews can load the image without anyone opening the document. Do not send the document by mail.
- Other programs, such as LibreOffice or a viewer in the browser, may not load linked images.
