chrome.extension.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.message == "chooseFile") {
        /* Creates an `input[type="file]` */
        var fileChooser = document.createElement('input');
        fileChooser.type = 'file';

        fileChooser.addEventListener('change', function () {
            console.log("file change");
            var file = fileChooser.files[0];

            var reader = new FileReader();
            reader.onload = function(){
                var data = reader.result;
                fields = $.parseJSON(data);
                // now send the message to the background
                chrome.runtime.sendMessage({message: "import", fields: fields}, function(response) {
                    console.log(response.response);
                });
            };
            reader.readAsText(file);
            form.reset();   // <-- Resets the input so we do get a `change` event,
                            //     even if the user chooses the same file
        });

        /* Wrap it in a form for resetting */
        var form = document.createElement('form');
        form.appendChild(fileChooser);

        fileChooser.click();
        sendResponse({response: "fileChooser clicked"});
    }

});