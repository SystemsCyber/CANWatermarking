1. Install the AWS SDK: 

   ``` bash
   php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
   php -r "if (hash_file('sha384', 'composer-setup.php') === 'e0012edf3e80b6978849f5eff0d4b4e4c79ff1609dd1e613307e16318854d24ae64f26d17af3ef0bf7cfb710ca74755a') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"
   php composer-setup.php
   php -r "unlink('composer-setup.php');"
   ```

2. Install the AWS sdk for php:

   ```bash
   composer require aws/aws-sdk-php
   ```

3. On top of any php file that uses the sdk include the following:

   ``` php
   <?php
      require '/s/chopin/b/grad/subhomuk/public_html/CANWatermarking/website/vendor/autoload.php';
   ?> 
   ```

4. Setup the credentials in the environment variables. This is needed as otherwise credentials may be leaked. Put the below mentioned exports in the ~/.bashrc file:

   ```bash
   export AWS_ACCESS_KEY_ID=AKIARNA4VTG7MXCKAUM7
   export AWS_SECRET_ACCESS_KEY=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
   ```

   Once done, run

   ```bash
   source ~/.bashrc
   ```

   

   