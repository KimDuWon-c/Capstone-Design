var url_link;
var apikey = "2b216836dde92f155d128f683ef784836f56a9bcb442b749959a5b3ec9e83da1";
chrome.contextMenus.onClicked.addListener(function (info, tab) {
	/// begin doing my testing for virus detection.
	/// Use Alerts at the moment.
	url_link = info.linkUrl;
	// check for api key value pair



});

chrome.contextMenus.create({
	id: 'open',
	title: 'Scan link with APT DETECT',
	contexts: ['link'],
});
