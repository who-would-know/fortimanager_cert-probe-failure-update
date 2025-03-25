## FortiManager Update: Set `cert-probe-failure = allow` in SSL Profiles

This script automates the process of logging into **FortiManager**, updating the **SSL Profile** to `cert-probe-failure = allow`, updating policies with the new profile, and installing the policy package.

### Description

#### This script automates the following tasks in FortiManager:

- Logs into **FortiManager**
- Checks if a cloned **SSL Inspection Profile** (from `certificate-inspection`) exists
- Creates or updates the cloned **SSL Profile** with `cert-probe-failure = allow`
- Finds **Firewall Policies** using `certificate-inspection` and updates them with the new SSL Profile
- Installs the **ADOM Policy Package** with changes

### Usage

#### Option 1: Run the Windows EXE

1. Download the **EXE** from the `/dist` folder
   - Click on `*.exe`, then click **"View Raw"** to download
2. **Run the EXE** and follow the on-screen instructions

#### Option 2: Run the script manually (or build EXE)

1. **Clone the repository** to your local machine (Windows if creating a Windows EXE)
   ```bash
   git clone https://github.com/who-would-know/fortimanager_cert-probe-failure-update.git
   cd fortimanager_cert-probe-failure-update
   ```
2. **Install** `pyinstaller`:
   ```bash
   pip install pyinstaller
   ```
3. See **"Build python to exe HOWTO.txt"** for PyInstaller commands
4. Run the generated EXE from the `/dist` directory

### Requirements

    Python 3.10
    FortiManager 7.0+
    FortiManager API access (R/W API user account)
    FortiGate Device Name must be displayed in FortiManager
