// AWS.config.region = 'us-east-1';

// var userPoolData = {
//     UserPoolId : 'us-east-1_CVvx2Qod7',
//     ClientId : '34084mof96h6lj1vs55ijafer'
// };


//var userPool = new AWS.CognitoIdentityServiceProvider.CognitoUserPool(userPoolData);


// var myCredentials = new AWS.CognitoIdentityCredentials({IdentityPoolId:'IDENTITY_POOL_ID'});
// var myConfig = new AWS.Config({
//   credentials: myCredentials,
//   region: 'us-west-2',
// });

// var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({apiVersion: '2016-04-18'});

// $(document).ready(function(){

//     function signin(email, password, onSuccess, onFailure) {
//         var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
//             Username: email,
//             Password: password
//         });

//         var cognitoUser = createCognitoUser(email);
//         cognitoUser.authenticateUser(authenticationDetails, {
//             onSuccess: onSuccess,
//             onFailure: onFailure
//         });
//     }

//   $('#signinForm').submit(handleSignin);

//   function handleSignin(event) {
//     var email = $('#emailInputSignin').val();
//     var password = $('#passwordInputSignin').val();
//     event.preventDefault();
//     signin(email, password,
//         function signinSuccess() {
//             console.log('Successfully Logged In');
//             window.location.href = 'device.html';
//         },
//         function signinError(err) {
//             alert(err);
//         }
//     );
// }

// });



AWS.config.region = 'us-east-1';
var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({apiVersion: '2016-04-18'});


$(document).ready(function(){

  $('#signinForm').submit(signin);

  function signin(event) {
    var email = $('#emailInputSignin').val();
    var password = $('#passwordInputSignin').val();
    event.preventDefault();
    cognitoidentityserviceprovider.initiateAuth(params = {
         AuthFlow: 'USER_PASSWORD_AUTH',
         AuthParameters: {'USERNAME':email,
                         'PASSWORD':password},
         ClientId: '34084mof96h6lj1vs55ijafer' 
       }, 
       function(err, data) {
          if (err) console.log(err, err.stack); // an error occurred
          else     console.log(data);           // successful response      
        }
    );
  };

});
