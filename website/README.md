# Switching between Subhojeet's (CS) and Dr. Daily's (ENGR) domains

1. On the COGNITO console

   1. Toggle the Callback urls

      * https://www.engr.colostate.edu/~jdaily/CANConditioner/device.html
        * This URL will most likely change to ~jdaily/CANWatermarking/website/home.html

      * https://www.cs.colostate.edu/~subhomuk/CANWatermarking/website/home.html

   2. Toggle the Signout urls

      * https://www.engr.colostate.edu/~jdaily/CANConditioner/index.html
        * This URL will most likely change to ~jdaily/CANWatermarking/website/index.html
      * https://www.cs.colostate.edu/~subhomuk/CANWatermarking/website/index.html



# General coding guidelines

## Steps to get the dev env ready

1. There are two git clones: one on your local machine ('local') and one on the public csu server ('public')
2. Open the local bsStudio project and do any edit html edits, and some javascript stuff. Set the export directly to public in 'Export options' and export.
3. Any javascripts edits should preferably be done on the public repo directly via Geany or Sublime etc.
4. Log in and navigate to the whatever page needed. Note the login is needed as it is at this stage that the auth-token is fixed in *localstorage*.
5. Preferably make only html edits via BSstudio and javascript edits via Geany, Sublime etc.
6. Add, commit, push the public repo first. Checkoout the local repo and then push add, commit, push.

# Upcoming Action Plans

## Allow company-wide access to assets (systems, devices etc) if 

1. They belong to company X [Has to be done either through Cognito triggers and/or DynamoDB]

​	**Organization table schema**

```json
{
  "id": {
    "S": ""
  },
  "Name": {
    "S": ""
  },
  "MX domains": {
    "SS": [

    ]
  }
}
```

1. User selects employer;

   * We add new required attribute 'employer'

   * This will either be a dropdown or a search & autocomplete field
     * By default this is None

2. If employer selected, user provides employer email

   * For this we add new required attribute 'company branded email'

   * Can be same as the login email
   * Once provided we check that the provided mx domain is in our Organization table
     * If not, user is notified
     * We will manually populate the Organization table when devices are provisioned to organizations
       * We will make our best effort to populate the MX domains but if we miss out some, users must reach us

3. If MX domain verified and if not same as login email, user verifies this email

2. Target asset is added by another employee of the same company and they have granted company-wide access

   * This another employee must have also gone through the previous step i.e. verification of employment

   * With the user logged in, on the 'view.html' page we make the ajax call to list_devices

   * list_devices does the following 

     * Gets the current users employer

     * For every device

       * If the device policy (a field in the Dynamodb as described below) does not permits read, we don't return this

         ```json
           "Company-wide-access-policy": {
             "Read": "False",
             "Modify": "False",
             "Delete": "False"
           }
         ```

     * We get the provisioner employer [*NOTE: that the a user can only be affiliated with one organization*]If these employers are same we grant access
     * NOTE: Updates to this device must be authorized through this same policy

## System and device association

1. User provides systemid on the device modal **(Supported)**
2. Data is sent over to ```manage``` API that does the following
   1. Checks if request is to add device to system
   2. If so, check if the system (found through input systemid) is provisioned by them or has a 'modify' company-wide-policy and they belong to the same company
   3. If so, do the requested, else notify the user that this system