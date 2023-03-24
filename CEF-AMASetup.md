## Stream Comment Event Format (CEF) with Azure Monitor Agent (AMA) (the helping hand guide). Authored by: Michael Crane and [Lorenzo Ireland](https://github.com/dcodev1702). ##

Many folks using Microsoft Sentinel have issues with clarity around the Common Event Format (CEF) via AMA and rightfully so. This article aims to clear any confusion for both Azure Commercial and Goverment tenants. See CEF-AMA [here](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-ama).

*Disclaimer* - In Microsoft Sentinel, the CEF connector is only giving you instructions to create a Data Collection Rule (DCR) and looking for the ingestion on a flag [e.g. CEF:]. It is NOT a true connector. You will have some manual work to do and this solution does work in Azure Government. 

*Pre-req* - Create a Ubuntu Virtual Machine (VM), I am using a Linux VM in Azure for this use case. If you want to use a Linux VM from on-premises, you will need to enroll that VM into Azure Arc so your on-premises resource can be managed in Azure.  You don't need anything crazy to keep the cost low for this use case / Proof of Concept (PoC). Being this is owned by the SecOps team, the VM lives within my SecOps subscription in Azure.

## CEF Setup on Ubuntu 22.04

```
# Secure Shell (SSH) to your Ubuntu VM. The following commands can be copied and pasted via your SSH session.

# Update/Upgrade System, if needed.
sudo apt-get update -y && sudo apt-get upgrade -y

# Reboot
sudo reboot

# Check if Python 3 is installed and syslog-ng or rsyslog (rsyslog by default) 
sudo apt install python3-dev rsyslog

# Install PowerShell 7.3.X
sudo snap install powershell --classic

sudo pwsh

install-module Az -Scope AllUsers -Force

```

## Creating the Data Collection Rule (DCR).

The DCR has to be in place first. Go to Azure Montior, scroll down on the left hand side and select "Data Collection Rule".  Create a simple syslog DCR and call it a day, as we will reconfigure it later. Once created, assign the Ubuntu VM to the DCR via "Resources" blade on your left hand side.  Allow some time for the AMA extension to be added to your Linux VM and the syslog data to ingest into Sentinel before moving onto the next step. 

*Instructions* - [here](https://learn.microsoft.com/en-us/azure/sentinel/forward-syslog-monitor-agent)

## Run the following on your Linux VM, AFTER you have successfully created the DCR. 

```
# Azure Commercial or Azure Goverment. The installation script configures the rsyslog or syslog-ng daemon to use the required protocol and restarts the daemon
sudo wget -O Forwarder_AMA_installer.py https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/Syslog/Forwarder_AMA_installer.py
sudo python3 Forwarder_AMA_installer.py 

```
# Edit the rsyslog or syslog-ng conf file. 
On the Ubuntu VM (server) you will see it has been changed to CEF by uncommented modules and inputs. Confirm changes: 'cat /etc/rsyslog.conf'

![](https://github.com/Cyberlorians/uploadedimages/blob/main/cefmagrsyslog.png)

# Setup the connector with the API - Reconfigure the DCR for CEF and NOT syslog. 

*PreReqs* - PowerShell, Az Module.

GET Request URL and Header - **Azure Commercial or Azure USGovernment** 
 
```
$environment = CHANGE ME TO -> 'AzureCloud' or 'AzureUSGovernment'
Connect-AzAccount -Environment $environment -UseDeviceAuthentication

# Get Azure Access (JWT) Token for API Auth/Access 
if($AzContext.Environment.Name -eq 'AzureCloud') {
    $resourceUrl = 'https://management.azure.com'
} else {
    $resourceUrl = 'https://management.usgovcloudapi.net/'
}
    
$token = (Get-AzAccessToken -ResourceUrl $resourceUrl).Token
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization","Bearer $token")

$ct = ‘application/json’
$subscriptionId= ‘SubscriptionIDofWhereTheDCRLives’
$resourceGroupName = 'RGofWhereTheDCRLives'
$dataCollectionRuleName = ‘CEF-CHANGEME-DCR’
$url = “$resourceUrl/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.Insights/dataCollectionRules/$($dataCollectionRuleName)?api-version=2019-11-01-preview”
$DCRResponse = Invoke-RestMethod $url -Method GET -Headers $headers
$DCRResponse | ConvertTo-JSON | Out-File "$(pwd).Path\cef-dcr.json"
```

# Reading the Request Body and make edits

You can follow the directions [here](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-ama#request-body). 

Edit and Notes: Where you see a RED dot, take not of the MSFT article and your changes according to yours. Below is an example. Make changes and save the file.

![](https://github.com/Cyberlorians/uploadedimages/blob/main/cefdcredit.png)

# PUT Request Body - **This is the same for any Azure Environment**

```
$json = Get-Content -Path ./cef-dcr.json -Raw
$DCRPUT = Invoke-RestMethod -Method ‘PUT’ $url -Body $json -Headers $headers -ContentType $ct
```

# Confirm changes have been made by reading the overview/JSON on your DCR rule in Azure Monitor.

![](https://github.com/Cyberlorians/uploadedimages/blob/main/CEFcompleteDCR.png)

# Test the connector [here](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-ama#test-the-connector)

# Confirm you are ingesting the CEF Logs into Sentinel.

![](https://github.com/Cyberlorians/uploadedimages/blob/main/SentinelCEFProof.png)

# Verify the connect is installed correctly, run the troubleshooting script w/ this command.
# This script will also send a generic CEF message which after a few minutes, show up in your Log Analytics Workspace.
# Keep in mind, you cannot use TCPDUMP on Azure, however, if you're Linux VM is on-premises, the script will sniff
# your traffic for 20 seconds looking for CEF messages, if nonee are found, it will send off a generic CEF message.

Azure Commercial
```
sudo wget -O cef_AMA_troubleshoot.py https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/CEF/cef_AMA_troubleshoot.py
sudo python3 cef_AMA_troubleshoot.py
```

Azure Government
```
sudo wget -O cef_AMA_troubleshoot.py https://raw.githubusercontent.com/Cyberlorians/Sentinel/main/Connectors/CEF/cef_AMA_troubleshoot.py
sudo python3 cef_AMA_troubleshoot.py
```
