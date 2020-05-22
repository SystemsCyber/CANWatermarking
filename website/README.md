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