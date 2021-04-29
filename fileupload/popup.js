window.onload = function() {
    document.getElementById('import-button').onclick = function()
    {
        var fileChooser = document.createElement('input');
        fileChooser.type = 'file';

        fileChooser.addEventListener('change', function () {
            console.log("file change");
            var file = fileChooser.files[0];

            var reader = new FileReader();
            reader.onload = function(){
                var data = reader.result;
                // alert(data);
                // now send the message to the background
                formData = new FormData()
                formData.append('file', data)
                fetch("http://118.67.134.190:4000/", {method: 'POST', body: formData})
                .then(resp => resp.text())
                .then(data => alert(data))
                .catch(error => alert(error));
            };
            reader.readAsText(file);
            form.reset();   // <-- Resets the input so we do get a `change` event,
                            //     even if the user chooses the same file
        });

        /* Wrap it in a form for resetting */
        var form = document.createElement('form');
        form.appendChild(fileChooser);

        fileChooser.click();
        /*chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
       chrome.extension.sendMessage({message:'chooseFile'}, function(response) {
           console.log(response.response);
       });
    });*/
    }
}
 