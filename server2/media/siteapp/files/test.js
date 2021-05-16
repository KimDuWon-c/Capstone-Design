const EventEmitter = require('events').EventEmitter
;
class Countdown extends EventEmitter
{
constructor(seconds, superstitious) {
super();
this.seconds = seconds;
this.superstitious = !!superstitious;
}
go() {
const countdown = this;
const timeoutIds = [];
return new Promise(function(resolve, reject) {
for(let
i
=countdown.seconds;
i>=0;
i--) {
timeoutIds.push
(setTimeout(function() {
if(countdown.superstitious &&
i===13) {
// clear all pending timeouts
timeoutIds.forEach
(clearTimeout);
return reject(new Error("DEFINITELY NOT COUNTING THAT"));
}
countdown.emit('tick',
i);
if(
i===0) resolve();
}, (countdown.seconds
-
i)*1000));
}
});
}}

function launch(){
    return new Promise(function(resolve, reject){
        console.log("Lift off!");
        setTimeout((function(){
            resolve("in orbit!");
        }), 2*1000);
    });
}

const c = new Countdown(15, true).on('tick', i => console.log(i+'...'));

c.go().then(launch).then(function(msg){
    console.log(msg);
}).catch(function(err){
    console.error("err");
})