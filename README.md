# AD-Search
 A powershell script utilizing AD cmdlets to search for information.

A small project used to find information about users or groups in an Active Directory invironment. The script is based on "read" rights only, so it's not possible to mess anything up.

Please feel free to use it as you please and modify it to make it suit your use case.

You might need to use `set ExecutionPolicy Unrestricted` in a powershell terminal to get it work.

### Installation of RSAT tools in Windows
For installation of the Active Directory module for Powershell you usually install it by installing the RSAT (Remote Server Administration Tool) package. To install RSAT in Windows 10, navigate to Settings application -> Apps -> Manage Optional Features -> click on Add a feature. Select the required RSAT packages, especially Active Directory Domain Services and Lightweight Directory Services, and click Install.

If you can't do it that way, you can also do it by using the powershell terminal as an administrator.

```powershell
net stop wuauserv
```

```powershell
net start wuauserv
```
Get a list of avaible packages.
```powershell
Get-WindowsCapability -Name RSAT* -Online``
```

```powershell
Add-WindowsCapability -online -Name "<tool name>"
```