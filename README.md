###Work in Progress
# NSX-T Configuration Automation Tool
This tool is a migration utility, that can read switch port informatiom from an excel file or a RV tools and create respective logical switches on NSX-T. This tool uses vmware/go-vmware-nsxt SDK

# Usage

## Clone this repo
```
git clone https://github.com/sbikram/nsxt.git
cd nsxt
go build main.go
```
## Create env variables
You need to define below env variable to s this tool can connect to NSX-T Manager
* NSXT_USERNAME - NSX-T user with access to create logical switches
* NSXT_PASSWORD - NSX-T password
* NSXT_MANAGER_HOST - IP or Hostname of NSX-T manager
* NSXT_ALLOW_UNVERIFIED_SSL - Bool(true or false), set this to false if NSX-T manager is using self-signed cert
* RVTOOLS_SHEET_NAME - Name of the sheet in RV_Rools excel sheet from where you want this tool to read switch port information

## Run the tool
Usage: nsxcfg -f <input_rv_tools.xlsx>

