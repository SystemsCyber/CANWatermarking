# AWS JS/Jquery SDK Guide for Cognito (As of May 2020)

====================================================================================

Pages are written in html, scripts in javascript and Jquery. Scripts must be included in the html page using the script tag.

# Sources

Sources of information vary widely as of now when it comes to the JS SDK but here is the current state of the affairs

* Reference getting started
  * https://aws.amazon.com/blogs/mobile/accessing-your-user-pools-using-the-amazon-cognito-identity-sdk-for-javascript/
* Jquery
  * API reference:  https://api.jquery.com/
  * User friendly learning: https://www.w3schools.com/jquery/jquery_get_started.asp
  *  A more or less comprehensible overview is also presented in this document.
* AWS Javascript SDK
  * Guide: https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/welcome.html
  * API reference: https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/
* AWS Cognito
  * User pools
    * Guide: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html
    * API reference: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/Welcome.html

There are two ways to migrate between the API references: 

In the AWS Cognito API reference, every action is linked with the corresponding JS API page

<img src="/home/subhojeet/.config/Typora/typora-user-images/image-20200502015459412.png" alt="image-20200502015459412" style="zoom:45%;" />

OR 

On the AWS Javascript SDK API reference page, click on the menu (three horizontal lines) button on the top right corner and browse/search the API

<img src="/home/subhojeet/.config/Typora/typora-user-images/image-20200502015649000.png" alt="image-20200502015649000" style="zoom:50%;" />

# IDE

<img src="/home/subhojeet/.config/Typora/typora-user-images/image-20200502020127793.png" alt="image-20200502020127793" style="zoom:50%;" />

Best case is to use Google Chrome. An example snapshot is provided above. Setup steps are as follows

1. On the 'Filesystems' tab as shown above and a folder, in this case the cloned git folder or whichever local folder you are using.
2. Thats it, double click the files and see them work. We do not need a server for this



# Setup

1. [Optional] Clone your repo from GITHUB
2. [Totally totally optional] Install ngnix if you prefer to view via a server instead. In general, because this is client-side development, Chrome does the job just fine. In case if you do use nginx, create a soft-link from the clones git path to under the '/var/www/html' directory which is the root path for nginx (command: ln -s <just_cloned_git_path> <desired_path_under_nginx_root>). For now lets call this path '*webpath*' -> /var/www/html/webpath
3. Create a JS directory under the *webpath* 
4. Download the latest (3.5.0) production Jquery API from https://jquery.com/download and place under the JS directory. Downloaded filename should end with "min.js"



# Steps

1. 

