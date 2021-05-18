document.addEventListener('DOMContentLoaded', function(){
    document.getElementById('import-button').onclick = function()
    {
        var fileChooser = document.createElement('input');
        fileChooser.type = 'file';

        fileChooser.addEventListener('change', function () {
            console.log("file change");
            var file = fileChooser.files[0];

            formData = new FormData()
            formData.append('file', file)
            fetch("http://49.50.166.66:8000/upload/", {method: 'POST', body: formData})
            .then(resp => resp.text())
            .then(data => {
                var split = data.split("\n")
                var id = split[0]
                var hash = split[1]
                chrome.tabs.create({url: "http://49.50.166.66:8000/upload/" + hash + "/" + id})
        })
            .catch(error => alert(error));
            
               // <-- Resets the input so we do get a `change` event,
                            //     even if the user chooses the same file
        });

        /* Wrap it in a form for resetting */
        

        fileChooser.click();
    }
});

 
document.addEventListener('DOMContentLoaded', function(){
    var button1 = document.getElementById("home-button");
	button1.addEventListener("click",function(){
        chrome.runtime.sendMessage({action: "HOME"}, function(response) {
		});
    });
});