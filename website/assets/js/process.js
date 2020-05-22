$(document).ready(function () {
    var url = window.location.pathname;
    file = url.substring(url.lastIndexOf('/')+1);
    // console.log(window.location);
    if (url.endsWith("home.html")){setToken();}
    else if(url.endsWith("CANConditioner/view.html")){getDevices();}
});


function setToken(){
    const urlParams = new URLSearchParams(window.location.hash);
    authable = urlParams.get('#id_token');
    localStorage.setItem("token", authable);
//     console.log("authToken: ");
//     console.log(authable);
// }

function getDevices(){
    // console.log("token ")
    // console.log(localStorage.getItem("token"));
    var token = localStorage.getItem("token");
    $.ajax({
                url: "https://jeg5qkwei4.execute-api.us-east-1.amazonaws.com/dev/list_keys",
                method: "GET",
                crossDomain: true,
                dataType: 'json',
                headers: {
                    'Authorization': "Bearer " + token,
                    
                }
            })
            .done( function(data){
                console.log(data);
            })
};