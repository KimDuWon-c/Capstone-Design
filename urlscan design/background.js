/*chrome.webRequest.onBeforeRequest.addListener(
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
*/




var url_link;
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
    console.log(sender.tab ?
        "from a content script:" + sender.tab.url :
        "from the extension");

    if (request.action === "FINISH"){
		chrome.tabs.create({url : url_link});
	}
    else if(request.action === "HOME"){
        chrome.tabs.create({url : "page_home.html"});
    }
    
});
chrome.contextMenus.onClicked.addListener(function (info, tab) {
	url_link = info.linkUrl;
    formData = new FormData()
            formData.append('testurl', url_link)
            fetch("http://49.50.166.66:8000/url/", {method: 'POST', body: formData})
            .then(resp => resp.text())
            .then(data => {
                chrome.tabs.create({url: "http://49.50.166.66:8000/url/" + data})
            })
});

chrome.contextMenus.create({
	id: 'open',
	title: 'Scan link with APT DETECT',
	contexts: ['link'],
});
