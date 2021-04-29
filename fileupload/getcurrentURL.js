function getCurrentTabURL(callback){
  var queryInfo = {
    active: true,
    currentWindow: true
  };
  chrome.tabs.query(queryInfo, function(tabs){
    var tab = tabs[0];
    var url = tab.url;
    callback(url);
  })
}
function renderURL(statusText){
  document.getElementById("i_result").innerHTML = statusText;
}

document.addEventListener('DOMContentLoaded', function(){
  chrome.tabs.executeScript(
    function(result){
        getCurrentTabURL(function(url){
        renderURL(url);
    });
    }
  )
});
   

