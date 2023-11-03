# AD-Search
A powershell script utilizing AD cmdlets to search for information. This project is based on the need too find information about users or groups in an Active Directory environment. The script is based on "read" rights only, so it's not possible to mess anything up and should be safe to use.

Please feel free to use it as you please and modify it to make it suit your use case.

You might need to use `set ExecutionPolicy Unrestricted` in a powershell terminal to get it work.

Please note that the different attributes must be populated in the Active Directory for this script to work.

## Installation of RSAT tools in Windows

This script is based on the cmdlet of the RSAT ActiveDirectory cmdlets, and to get this script to work you need the RSAT tools.

To use the Active Directory module for Powershell, you need to install the RSAT (Remote Server Administration Tool) packages. To install RSAT in Windows 10, navigate to Settings application -> Apps -> Manage Optional Features -> click on Add a feature. Select the required RSAT packages, especially *Active Directory Domain Services and Lightweight Directory Services*, and click Install.

There might be soom instances where you can't do it that way, then you can also do it by using the Powershell terminal as an administrator.

```powershell
net stop wuauserv
```

```powershell
net start wuauserv
```
Get a list of avaible packages.
```powershell
Get-WindowsCapability -Name RSAT* -Online
```
In this case you want the *Active Directory Domain Services and Lightweight Directory Services Tools*.
```powershell
Add-WindowsCapability -online -Name "<tool name>"
```

## Logging
There are a basic logging function in this script, the log will be saved at the `%temp%/adsearch/logfile.txt` which will look like:
```
2022-03-14 15:30:00 - User Search : <username>
```
The following functions will be logged:

- Search for username
- Search for an Employee number
- Search for a group
- List groups a specific user is a member of
- List members of a group
- Full report on an user
- Get a "tree" structure of what OU's a user is a member of