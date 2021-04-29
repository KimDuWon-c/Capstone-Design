chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if(request.action == "gogo"){
        sendResponse({resp:"hihi"});
    }
    
    if (request.message == "import") {
        fields = request.fields; // use the data
        sendResponse({response: "imported"});
    }

});