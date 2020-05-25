/* --- --------------- Globals ------------- */

var devices = []
/* --- --------------- End Globals ------------- */


$(document).ready(function () {
    var url = window.location.pathname;
    if (url.endsWith("home.html")){setToken();}
    else{
		//$("#header").load("nav-notify.html"); 
		var token = localStorage.getItem("token");
        token=""
		if (token == null) { 
            errorNotify('Invalid credentials!!');
        }else{
            //ALTER
            //if(url.endsWith("CANConditioner/view.html")){
                organizeView(token);
            //}
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
    // Initialize map
    var map = L.map('map').setView({lon: 0, lat: 0}, 2);

    // add the OpenStreetMap tiles
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19,
    attribution: '&copy; <a href="https://openstreetmap.org/copyright">OpenStreetMap contributors</a>'
    }).addTo(map);

    // show the scale bar on the lower left corner
    L.control.scale().addTo(map);
    
    //Get device data
    devices = [
{
    "type": "CANconditioner",
    
    "encrypted_device_password": "Z0FBQUFBQmVqVUpQRWNmVlVTUDJaTFg3QnQ4d0ZwUnRQRFZrSUFaOG1CSHNwdzczWlZmMzhKMF9pQzR5ZEhyT3ctOHlSbXhER0pqVHJOcWR4dHpId2lHTGQ4S2lQYnpzZUE9PQu003du003d",

 "encrypted_device_public_key": "Z0FBQUFBQmVqVUpQb3BaMlliOG1LMGlzYnh6VUlWbEk0NmQ4TS1wb3RtQW1VcXhabVc5eFBEcjZHUFJvQWRpUWpwZGtBQzU4ZGQzYUZyQmUxMUlvMG5YRjlTV2k0SW9XQ0xoeEE0S0RGMFEwZjNaMm9zV1UtNXRSWEpYZ0ZVTVZKWnRuOHhablB2UkFVWnVfRjVHNExiS0FiVlVjSUhyVzZRZzZHUnczM1FiQ0hZNkx1WTBYbzM4PQu003du003d",

 "encrypted_server_pem_key": "Z0FBQUFBQmVqVUpQWmIxMVBxX2F1OWY5OC1qWU5OV21HVmxmVWFhZFJvaThHMnpya3FyZjJVczRKbkdGMzE2MkFXS3h0NllUTDhqVnZmQVhaRmpBVjMtWFd2eld3eFBaam5pLVFYNHFscncwS3FjeUgwX0JHMU43cU9tNl9KS2tLVXFvUFhraXdmX1M0QjVhNG4wVlIxYmVaZVhkLUw3b1RXeG8zSXNBQ0lyTnlVellmSkxSZHlVX3RhZC1fcVdZNHQzcXpoazJjV1I5RVRrRTlfeW9LbEV3MGprVi1RSjQ5OXZNTDh6Ui0zWnlocy12cEo0b0NwWFhJdHFITElSMkR4Tng4NDctZDRLeTE5T0RhcEhubjR1MVVuX3lUVUVWM2NHSER4Ny1ES1cxcTZhejVkY3VUcnJHYXFaaDhlOXNiVGI5dHEzM0xvZXhSOW9EOUZfY1A3R3QybTB5ZXlZVi1tZFhsRExUNUR1Nll3aTJ1UWJUb1NMc3lOUDd5eC1INGJXcEpSMFIwWjhKc3p2NE9rc3RDb0FfTG5HU21SSDBDcTU2dk56bHo3NkJxa0NCZlpSbFVnWjVFUjNvUjZlSXgySl80RFZaSkxfUzlmUEhocVl4YlAyTG5mcS1kb0ZkNm4xaG82VkFscHUzWW1tSUowUW5PbGowWUh3bFBrUXVrOEFEZFBQbnhzNGhkYXQ2SmFLYTM3Tkw3Q2pGa1UyNW8xLUVhclZVMXNPX2ljYUJWckVhUzFtMmd1WlhpeUlnUFUxRUFYaEtHWjg1MXd2N29sLUtmd3FOQmNwZ1lOeFBrQT09",

 "encrypted_data_key": "AQIDAHiv1Y+2M3JZQN4khYeuDzjqNfx2dEbe/7e4YSSN1sMrlQGJlHoQO8n1Uov/Pg/rX0H5AAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMLxvvnF4kwa/q1t6sAgEQgDstX6iNulQLi0Rk4Pjf07OxTiMD8vL/PvhMHbE+826j1+QK8f3V3pVt8mS7BQXNCglyFlywVw8MimnFNgu003du003d",

 "sourceIp": "71.196.239.201",

 "encrypted_key_code": "Z0FBQUFBQmVqVUpQVzBCMWZyTEticVRZcXJ3V21xZk01Vkd2aGdYNUFqTGl6Vl8zQzZ1UUJMQ3RJZF83VjcxQWtUY2xDTG9WNUhZOUF2Mmg1UFpxYnFPVTlQTUFCUUV5djNHUVp2UjBXalE4a1RkX2k5eEE1T2c9",

 "id": "0123308F0B3BD236EE",

 "email": "subhojeet.m@gmail.com",
 
 "location": {"lat":40.5815,"lon":-105.1042},

 "encrypted_device_code": "Z0FBQUFBQmVqVUpQeFVXWXN6QXk2NXlkRGpOX0RrRTUxbHhMWmg1QkFhUGY3d1hkN0xMRWtsSmtFcWxlMHIzOXZEdjI1ZFpfWWRubmNzbWljQWs3RXVqTmZWOHlma2FKLXc9PQu003du003d"
 },

 {
     "type":"CanConditioner",
     
     "encrypted_device_password": "Z0FBQUFBQmVoNXNaSDBkVUR3b3E4TERWS0lnQV93SDM5M2R6Rjh2eGZoTUxraVl5b21SU1BnRHpPbGR2Wnc3UXNxa1hvQjRSQmhCMTdsblRNR3BHQkNXWUkwX3A2QlJTZEE9PQu003du003d",

 "encrypted_device_public_key": "Z0FBQUFBQmVoNVpuYTBRc3lZYTMzQXlkVDNMTlgtclRVR0E4Nno4V3c2bDBvWjFRVnhTTmRQUF9qSEV0cXB5TzUxOHExYUhfSDY5VGxMWjRYNU5sSC1EYlJSMk5JWXhqcTY4WmNQV0daN0pkZWdzRUNMNUdrcllZVzlUTkhQclNhSTA4RWVJRG5kSmR5MElGSkFKMFFvNHA0RUNvdjcwWnZBcHk0eXV6dE9oZUhtSmxaUy1aUmhVPQu003du003d",

 "encrypted_server_pem_key": "Z0FBQUFBQmVoNXNaaUhOa0NvZlVjeUpMM3Z6ZlR4ZTV6SGxIRDJBSzlUeFJWM2V6UkZjRkRHSE5HNWcwSy1fZTFfcUx2LUdTU05EZDFzS3hNNUJWbG83RGZxa0VJRmVyNmJ6czhnUzVuQTBocENSeDlVRzVFR3hXMFk4MW1JWlA2WFloRVozR0JWclRZNHN5Z0hOMDFIc2ZjeTk0SWlITmYxN0tDaVpBcllCRHp0TWgxbnhhZzdEMVItbUh5Yko3Z0wwS3RGc01TNnZzTEpHdnc4aE9FOFFlRmlyb1RHckJ1dVVYMi1wNEtmSVA4Z0dCcVY0VzJya0Ftem84M2hGT3VNZUh5LTFxcFlma0s2dnBEcE9mRmdidlFua3dHN3l1S0pyYkV5RTRvYUI1RGRGY2tWUEx3TmxJZ1ZmT2VndEFWVzVtNktlSzR0bWdWM24zSXV5NTdZcGc3bzA4VEpQZWNUSkVBNWhwZU53SWk4bFVONFJuVmhPb1d0T3Nsa1F6dnZHbmlfTnAxNk91YjRlZ1hseWFyWGh2XzZ5NzJod1I1VjNLSTJGNnMxNUhMQTFWSG9XVWo4U25LQnBEclJUTGNVVV9qZE9KX1pJRzFqTjdyN29kblhYRG1xdUhFaU85eUc0MGJEZERqU1llRDFjVUs2M2dSZzlBNWNwZzBtSm9aaTJhUUtjR25NbmlVeXB5UkIzYmUtSXVoOV9pWHluZjcxYXpqTC04RzgtXzhQTnVPbXRwMV9DZ0lFa3EtRUQ4X1lWNDlzaDd6bFAwb3NJdWRDUFNVQklFUmhTSnoxTHItQT09",

 "encrypted_data_key": "AQIDAHiv1Y+2M3JZQN4khYeuDzjqNfx2dEbe/7e4YSSN1sMrlQEhB+iVIfKwxuxKmT+kcpnOAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM0w3rk4PiJ4Hh/c2xAgEQgDvUzJOBxoeU8kROWPdRJyU2yYfPoZWafz3a+yNaePDnAkJddcGskq2fZRocEWgDdH6MumDXknZ1llo3Kwu003du003d",

 "sourceIp": "71.196.239.201",

  "location": {"lat":40.5377,"lon":-105.0546},
  
 "encrypted_key_code": "Z0FBQUFBQmVoNXNaeDZxSUJOUnRLSF9NN1RQbnJYYkNjbE0zQmhSLW1Yb3RHYW5wdE5aX000djFiSEhoMnBVT1RlbUVOVGc0T3FuanI3bGFOUnFuSV9QTU00VzZVZ0hhQ3Baay1yeWJPU21VRUUwNF9iVTJfbHM9",

 "id": "0123345D586AD20EEE",

 "email": "jeremy.daily@colostate.edu",

 "encrypted_device_code": "Z0FBQUFBQmVoNVpuZlFMZng3b2hCTjBZOS1HOFRPYTVSUXBITkRpbDhmS1lzbmNDMldXY2lzaWVMdURwWktsTkIyRHNDb1pBeU9YQWcyYllMc2RSZl9NQzFLZ01nVzRvQ0E9PQu003du003d"
 
 }
]

    //ALTER
    //Currently hashing to avoid ajac CORS issues 
    /*
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
                devices = data        
        // console.log(data);
            });
        */
    
    //Set device data in table
    for (i = 0; i < devices.length; i++) {
        $('#devtab').append('<tr style = "border-width: 1px; border-radius: 50px; border-color:black;padding: 10px; cursor:pointer;font-size: 15px; box-shadow: 0 2px #666;">' +
        '<td index=' + i.toString() + ' onclick="showDeviceInfo(this.getAttribute(\'index\'))"><p style="font-size:15px; font-family:Times New Roman">' + devices[i]['id'] + '</p></td><td><label class="switch"><input id="show" type="checkbox" onclick="showOnMap("show")"><span class="slider round"></span></label></td><td><label class="switch"><input id="show_prv" type="checkbox" showOnMap("show_prv")><span class="slider round"></span></label></td>'
     + '</tr>');
    }
    
}


function showOnMap(element){
    var checkBox = document.getElementById(element);
    if (checkBox.checked == true){
 L.marker({"lat":40.5815,"lon":-105.1042}).bindPopup("CANDEV").addTo(map);
    }
}


function showDeviceInfo(index){
    $('#email').val(devices[index]['email']);
    $('#encrypted_data_key').val(devices[index]['encrypted_data_key']);
    $('#encrypted_device_code').val(devices[index]['encrypted_device_code']);
    $('#encrypted_device_password').val(devices[index]['encrypted_device_password']);
    $('#encrypted_device_public_key').val(devices[index]['encrypted_device_public_key']);
    $('#encrypted_key_code').val(devices[index]['encrypted_key_code']);
    $('#encrypted_server_pem_key').val(devices[index]['encrypted_server_pem_key']);
    $('#sourceIp').val(devices[index]['sourceIp']);
    $('#devmod').modal('show');
}

