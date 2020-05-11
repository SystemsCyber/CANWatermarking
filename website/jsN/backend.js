///*global CANConditioner _config AmazonCognitoIdentity AWSCognito*/
/*global AWS*/

//var CANConditioner = window.CANConditioner || {};

//~ var onfig = new AWS.Config({
  //~ credentials: new AWS.CognitoIdentityCredentials({IdentityPoolId: 'us-east-1:c58ce90c-3e93-44f9-b005-edfa473a695b'}), 
  //~ region: 'us-west-1'
//~ });


//~ var getIdParams = {
  //~ IdentityPoolId: IDENTITY_POOL_ID,
  //~ AccountId: ACCOUNT_ID
//~ };

//~ var cognitoidentity = new AWS.CognitoIdentity({apiVersion: '2014-06-30'});

//~ cognitoidentity.getId(getIdParams, function(err, data) {
  //~ if (err) {
	//~ console.log("Error" + err);
  //~ } else {
	//~ console.log("Cognito Identity ID is " + data.IdentityId);
  //~ }
//~ });

$(document).ready(function(){

	var IDENTITY_POOL_ID = 'us-east-1:c58ce90c-3e93-44f9-b005-edfa473a695b';
//var ACCOUNT_ID = '096696900030';
var REGION = 'us-east-1';

// Initialize the Amazon Cognito credentials provider
AWS.config.region = REGION; // Region
AWS.config.credentials = new AWS.CognitoIdentityCredentials({IdentityPoolId: IDENTITY_POOL_ID,});

	
	displayDevices();
});

function displayDevices(){
	
	var authable = ""
	const urlParams = new URLSearchParams(window.location.hash);
	//If receiving the token directly,
	authable = urlParams.get('access_token');
	//else get the secret and send to the lambda which will exchange it to get a token
	//authable = urlParams.get('secret_code');
	
	var lambda = new AWS.Lambda({apiVersion: '2015-03-31'});

	 var params = {
	  FunctionName: "auth", 
	  Payload: authable, 
	  Qualifier: "1"
	 };
	 lambda.invoke(params, function(err, data) {
	   if (err) console.log(err, err.stack); // an error occurred
	   else     console.log(data);           // successful response
	   /*
	   data = {
		Payload: <Binary String>, 
		StatusCode: 200
	   }
	   */
	 });
	
	
    //~ var poolData = {
        //~ UserPoolId: _config.cognito.userPoolId,
        //~ ClientId: _config.cognito.userPoolClientId
    //~ };
	//~ console.log( _config.cognito.userPoolId);
	//~ console.log( _config.cognito.userPoolClientId);

    //~ var userPool;

    //~ if (!(_config.cognito.userPoolId &&
          //~ _config.cognito.userPoolClientId &&
          //~ _config.cognito.region)) {
        //~ $('#noCognitoMessage').show();
        //~ return;
    //~ }

    //~ userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    //~ if (typeof AWSCognito !== 'undefined') {
        //~ AWSCognito.config.region = _config.cognito.region;
    //~ }

	//~ var cognitoUser = userPool.getCurrentUser();
	
	//~ console.log('user: ', cognitoUser)
	
    //~ CANConditioner.authToken = new Promise(function fetchCurrentAuthToken(resolve, reject) {
        //~ var cognitoUser = userPool.getCurrentUser();

        //~ if (cognitoUser) {
            //~ cognitoUser.getSession(function sessionCallback(err, session) {
                //~ if (err) {
                    //~ reject(err);
                //~ } else if (!session.isValid()) {
                    //~ resolve(null);
                //~ } else {
                    //~ resolve(session.getIdToken().getJwtToken());
                //~ }
            //~ });
        //~ } else {
            //~ resolve(null);
        //~ }
    //~ });
    
    //~ console.log("authToken: ");
	//~ CANConditioner.authToken.then(function(data) {
		//~ console.log(data);
	//~ }).catch(function(err) {
		//~ console.log(err);
	//~ });
	//~ //console.log(CANConditioner.authToken);
	//~ //CANConditioner.authToken.resolve('fulfilled').then(function(value){console.log(value);});
}
