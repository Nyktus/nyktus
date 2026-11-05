## Story

Link an image in a Word document that you write yourself. This deception has no file to download, so that the document fits where you place it. The URL of the image belongs to an image honeytoken. It always answers with an invisible image of one pixel. Word loads a linked image from its URL whenever it opens the document, and the request raises an event.

## Setup

1. Create the image honeytoken "Image". Its URL replaces `Honeytoken-URL` below.
2. Write the document. Give it content that an intruder wants to read where you place it, such as salary figures, a list of contacts for emergencies or the plan of a project. A document that holds nothing but an image stands out.
3. Place the cursor at an inconspicuous spot, for example at the end of the document, and press **Ctrl+F9**. Word inserts an empty field `{ }`.
4. Write between the braces, with the URL of the honeytoken instead of the placeholder:

   ```
   INCLUDEPICTURE "Honeytoken-URL" \d
   ```

   `\d` keeps Word from storing the image in the document, so that it loads it again with every opening.
5. Press **F9** to update the field, and save the document as `.docx`.
6. Place the document where an intruder searches for valuable data, such as a file share of the finance or personnel department, a document management system or a backup.
7. Record in the notes of the scenario where you placed the document.

## Testing

Open the document in Word on a computer with access to the internet and click `Enable Editing`. Within a minute, the scenario shows an incident. Close the incident after the test.

To check only the honeytoken, run `curl Honeytoken-URL`, with the URL of the honeytoken.

## Limits

- Word opens documents from the internet and from some network shares in `Protected View`, which loads no images. Only `Enable Editing` sends the request.
- Mail gateways and previews can load the image without anyone opening the document. Do not send the document by mail.
- Other programs, such as LibreOffice or a viewer in the browser, may not load linked images.
