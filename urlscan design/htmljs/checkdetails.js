var testArray = [
    {'ProgramName' : 'anti', 'Details' : 'Malware'},
    {'ProgramName' : 'anti2', 'Details' : 'Phishing'},
]
var programName = [
    {'id' : 'Program Name', 'de' : 'Details'},
]
var numberof = [
    {'id' : '위험을 탐지한','text' :' 프로그램 수 : '}
]
function buildTable(data) {     
    var table = document.getElementById('table1'); 
    var w = `<tr>
             <th>${numberof[0].id}<br>${numberof[0].text}</th>
             <th>${data.length}</th>  
             </tr>`
    table.innerHTML += w;         
    var r = `<tr> 
             <th>${programName[0].id}</th> 
             <th>${programName[0].de}</th> 
             </tr>`
    table.innerHTML = table.innerHTML + r;      
    for (var i=0; i < data.length; i++) {
         var row = `<tr> 
                    <td>${data[i].ProgramName}</td> 
                    <td>${data[i].Details}</td> 
                    </tr>`
                    table.innerHTML += row;
        } 
    }

document.addEventListener('DOMContentLoaded',function(){
	var button1 = document.getElementById("danger");
	button1.addEventListener("click",function(){
       buildTable(testArray);
       button1.disabled = 'disabled';
});
});

