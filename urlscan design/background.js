var url_link;
var apikey = "2b216836dde92f155d128f683ef784836f56a9bcb442b749959a5b3ec9e83da1";
function r(tableId){
    chrome.tabs.update(tabId,{
        "url": redirectUrl
    });
}
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
    console.log(sender.tab ?
        "from a content script:" + sender.tab.url :
        "from the extension");

    if (request.action === "FINISH"){
		chrome.tabs.create({url : url_link});
	}
});
chrome.contextMenus.onClicked.addListener(function (info, tab) {
	url_link = info.linkUrl;
	chrome.tabs.create({url : "page1.html"});
});

chrome.contextMenus.create({
	id: 'open',
	title: 'Scan link with APT DETECT',
	contexts: ['link'],
});
