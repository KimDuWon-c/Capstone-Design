
function buildTable(prog, type) {     
	var test = prog;
	var test2 = type;
	console.log(test);
	console.log(test2);
    var table = document.getElementById('table1'); 
    var w = `<tr>
             <th>${"위험을 탐지한"}<br>${"프로그램 수"}</th>
             <th>${test.length}</th>  
             </tr>`
    table.innerHTML += w;         
    var r = `<tr> 
             <th>${"Program Name"}</th> 
             <th>${"Details"}</th> 
             </tr>`
    table.innerHTML = table.innerHTML + r;      
    for (var i=0; i < test.length; i++) {
         var row = `<tr> 
                    <td>${test[i]}</td>
		    <td>${test2[i]}</td>
                    </tr>`
                    table.innerHTML += row;
        } 
    }
