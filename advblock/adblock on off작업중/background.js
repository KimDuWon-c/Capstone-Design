
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        if(!enabled){
	        return { cancel: false };
        }
        console.log("I am going to block:", details.url)
        return {cancel: true};
    },
    {urls: blocked_sites},
    ["blocking"]
    
)