$(document).ready(function () {
    var url = window.location.pathname;
    if (url.endsWith("home.html")){setToken();}
    else{
		//$("#header").load("nav-notify.html"); 
		var token = localStorage.getItem("token");
		//Update this token everytime during dev to make sure we do not have to go back and forth the login page everytime. Also delete this assignment when in production.
		//token = "eyJraWQiOiJKN0lcL0NmR2lEcHZETVk1b3ZYREVXajNPUlwvaEUwaTR2b0JBTnR6WFRrejA9IiwiYWxnIjoiUlMyNTYifQ.eyJhdF9oYXNoIjoib1lNOUJodmRFdHRxcEVQWEZhUGNpdyIsInN1YiI6IjNiNmRmMWJlLWEwYjUtNGVmZC05YzI5LTE5YmY3OGVhODdkZCIsImF1ZCI6IjIxM2lmbjBtamhiNjRtc2pmcDFiZWdlMWViIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV2ZW50X2lkIjoiMmEzNTJkY2YtYTdmZi00M2QxLTk4Y2EtOTZmNWFhMGE4YjFjIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE1OTAzNzE3NTMsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX2h3akxFM2tKWSIsImNvZ25pdG86dXNlcm5hbWUiOiIzYjZkZjFiZS1hMGI1LTRlZmQtOWMyOS0xOWJmNzhlYTg3ZGQiLCJleHAiOjE1OTAzNzUzNTMsImlhdCI6MTU5MDM3MTc1MywiZW1haWwiOiJzdWJob2plZXQubUBnbWFpbC5jb20ifQ.jglJga6TkfrDIC1CIwZFRdesdN3zDF9q1fnLRJ9pk-PDKb2BY1xyY0PqP9MgPkpXPdWD7X29p7mcwPgAqZfmWf9SShU8-KTpanuiMhwv3W_ZrvQ3HoeytEzg9lGfZYKtSe-ySz1S8FKJO40ZYmiHUuXvQqrcIKNwBLj4ar-MK0b58p6WAkq8JzZPwSY1lQZgiC-K4vWiuZIGwjRXMzGM9_F6BDTu-kpPJoAcc84HtM_6HMi7VuhAIczwy2MRuzQ-qNNM_8EvS3hzJjLKrrKXXuCwVDJkIRivx51VilH9rFtrII2L1T6atclcNMyDw51MLtCv6XNdHK6ZDwghqwgkEw";
		if (token == null) { 
            errorNotify('Invalid credentials!!');
        }else{
            if(url.endsWith("CANConditioner/view.html")){organizeView(token);}
        }
		
	}
});


function errorNotify(str){
    $("#notify-header").text("Error!!");
    $('#notify-content').text(str);
    $('#notify').modal('show');
}

function setToken(){
    const urlParams = new URLSearchParams(window.location.hash);
    authable = urlParams.get('#id_token');
    localStorage.setItem("token", authable);
}



function organizeView(token){    
//     // Initialize map
//     var map = L.map('map').setView({lon: 0, lat: 0}, 2);

//     // add the OpenStreetMap tiles
//     L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
//     maxZoom: 19,
//     attribution: '&copy; <a href="https://openstreetmap.org/copyright">OpenStreetMap contributors</a>'
//     }).addTo(map);

//     // show the scale bar on the lower left corner
//     L.control.scale().addTo(map);

//     // show a marker on the map
//     L.marker({lon: 0, lat: 0}).bindPopup('The center of the world').addTo(map);
    
    //Get device data
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
            });
};
