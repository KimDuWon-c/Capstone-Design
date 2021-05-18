chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        if(!enabled){
	        return { cancel: false };
        }
         return {redirectUrl: chrome.extension.getURL("page_easy.html") };
    },
    {urls: blocked_sites},
    ["blocking"]
)
function r(tableId){
    chrome.tabs.update(tabId,{
        "url": redirectUrl
    });
}
chrome.extension.onRequest.addListener(function (request, sender, sendResponse) {

    if (request.redirect) {
            chrome.windows.getCurrent(function(w){
                chrome.tabs.query({windowId : w.id}, function(t){
                    r(t.id);
                });
            });
    }
    sendResponse({
        redirected: redirectUrl
    });
})