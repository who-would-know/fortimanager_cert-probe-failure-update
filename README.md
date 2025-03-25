FortiManager Update SSL Profile cert-probe-failure = allow
This script automates the process of logging into FortiManager, updating SSL Profile to cert-probe-failure = allow, updating policies with new profile, installing policy package

Description
The script streamlines the process of managing address objects in FortiManager by:

    Logging into FortiManager
    Checks if a clone ssl inspection profile of certificate-inspection exists or not
    Update clone ssl profile or create then update ssl profile with cert-probe-failure = allow from default
    Find Firewall Policies with certificate-inspection and update with new SSL Profile
    Installs ADOM Policy Package with changes

Usage

    Option 1) Python Windows EXE file.
            Download EXE Program under /dist folder (Click on *.exe then click on View Raw Link to DL)
            Double click EXE file follow instructions

    Option 2) Run locally via python or create EXE via pyinstaller
            Clone the repository to your local machine (Windows if creating Windows EXE)
            pip install pyinstaller
            See 'Build python to exe HOWTO.txt' file for pyinstaller command
            run EXE file under created /dist

Requirements

    Python 3.10
    FortiManager 7.0+
    FortiManager API access with R/W API user account.
    FortiGate Device Name displayed in FortiManager
