<#
.SYNOPSIS
A script to use as a daily driver when troubleshooting or engaging with users during support.

.DESCRIPTION
This script is made to help during support or find infomation about users or group when troubleshooting for errors or similar.
It is dependent on the Module "ActiveDirectory" and its cmdlets which is used to gather information and display it.

More information can be found at https://https://github.com/clausmalver/AD-Search

Thanks!

.NOTES
Script Name: ad_search.ps1
Author: Claus Malver
Version: 0.6.5
Last Modified: 2023-11-02
#>

# Check if the ActiveDirectory module is available
if (-not (Get-Module -Name ActiveDirectory)) {
    Write-Host "The ActiveDirectory module is not available. Please visit the following website for installation instructions:"
    Write-Host "Website: https://github.com/clausmalver/AD-Search/blob/main/README.md"
    exit
}


function Search-User {
    param (
        [string]$username
    )

    try {
        $user = Get-ADUser -Filter {SamAccountName -eq $username} -Properties DisplayName,LastLogon,WhenCreated,Enabled,UserPrincipalName,EmailAddress,LockedOut,Manager
        if ($user) {
            $fullName = $user.DisplayName
            $lastLogon = [DateTime]::FromFileTime($user.LastLogon)
            $creationDate = $user.WhenCreated
            $enabled = $user.Enabled
            $emailAddress = $user.EmailAddress
            $lockedOut = if ($user.LockedOut) { "Locked Out" } else { "Not Locked Out" }
            $manager = $user.Manager

            # Determine the account status
            $accountStatus = if ($enabled) { "Enabled" } else { "Disabled" }

            Write-Host "User: $fullName"
            Write-Host "Email Address: $emailAddress"
            Write-Host "Last Active: $lastLogon"
            Write-Host "Created: $creationDate"
            Write-Host "Account Status: $accountStatus"
            Write-Host "Locked Out Status: $lockedOut"
            Write-Host "Manager: $manager"
        } else {
            Write-Host "User not found."
        }
    } catch {
        Write-Host "An error occurred while searching for the user: $_"
    }
}

function Search-Group {
    param (
        [string]$groupname
    )

    try {
        $group = Get-ADGroup -Filter {SamAccountName -eq $groupname} -Properties Members, ObjectGUID, Description

        if ($group) {
            $membersCount = $group.Members.Count
            $guid = $group.ObjectGUID
            $description = $group.Description

            Write-Host "Group: $groupname"
            Write-Host "Members Count: $membersCount"
            Write-Host "GUID: $guid"
            Write-Host "Description: $description"
        } else {
            Write-Host "Group not found."
        }
    } catch {
        Write-Host "An error occurred while searching for the group: $_"
    }
}
function Get-UserGroupsList {
    param (
        [string]$username
    )

    try {
        $user = Get-ADUser -Filter {SamAccountName -eq $username} -Properties MemberOf

        if ($user) {
            $userGroups = $user.MemberOf | ForEach-Object {
                $group = Get-ADGroup -Identity $_ -Properties Name
                [PSCustomObject]@{
                    'Group Name' = $group.Name
                }
            }

            $userGroups | Format-Table -AutoSize
        } else {
            Write-Host "User not found."
        }
    } catch {
        Write-Host "An error occurred while listing user's groups: $_"
    }
}
function Get-GroupMemberslist {
    param (
        [string]$groupname
    )

    try {
        $group = Get-ADGroup -Filter {SamAccountName -eq $groupname} -Properties Members

        if ($group) {
            $members = $group.Members | ForEach-Object {
                $user = Get-ADUser -Identity $_ -Properties SamAccountName, DisplayName, LastLogon
                [PSCustomObject]@{
                    'Username' = $user.SamAccountName
                    'Full Name' = $user.DisplayName
                    'Last Active' = [DateTime]::FromFileTime($user.LastLogon)
                }
            }

            $members | Format-Table -AutoSize
        } else {
            Write-Host "Group not found."
        }
    } catch {
        Write-Host "An error occurred while listing group members: $_"
    }
}
function Get-UserReport {
    param (
        [string]$username
    )

    try {
        $user = Get-ADUser -Filter {SamAccountName -eq $username} -Properties DisplayName,UserPrincipalName,LastLogon,WhenCreated,Enabled,LockedOut,PasswordLastSet,PasswordNeverExpires,PasswordExpired,EmailAddress,Manager

        if ($user) {
            $fullName = $user.DisplayName
            $userPrincipalName = $user.UserPrincipalName
            $lastLogon = [DateTime]::FromFileTime($user.LastLogon)
            $creationDate = $user.WhenCreated
            $accountStatus = if ($user.Enabled) { "Enabled" } else { "Disabled" }
            $lockedOut = if ($user.LockedOut) { "Yes" } else { "No" }
            $passwordLastSet = [DateTime]::FromFileTime($user.PasswordLastSet)
            $passwordNeverExpires = $user.PasswordNeverExpires
            $passwordExpired = $user.PasswordExpired

            Write-Host "User Report for: $username"
            Write-Host "Full Name: $fullName"
            Write-Host "User Principal Name: $userPrincipalName"
            Write-Host "Email Address: $emailAddress"
            Write-Host "Last Logon: $lastLogon"
            Write-Host "Created: $creationDate"
            Write-Host "Account Status: $accountStatus"
            Write-Host "Locked Out: $lockedOut"
            Write-Host "Password Last Set: $passwordLastSet"
            Write-Host "Password Never Expires: $passwordNeverExpires"
            Write-Host "Password Expired: $passwordExpired"
            Write-Host "Manager: $manager"
            
        } else {
            Write-Host "User not found."
        }
    } catch {
        Write-Host "An error occurred while generating the user report: $_"
    }
}
function Get-MyUserInfo {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $user = Get-ADUser -Filter {SamAccountName -eq $currentUser.Name} -Properties DisplayName,UserPrincipalName

    if ($user) {
        $fullName = $user.DisplayName
        $userPrincipalName = $user.UserPrincipalName

        Write-Host "User Information for: $userPrincipalName"
        Write-Host "Full Name: $fullName"
        Write-Host "User Principal Name: $userPrincipalName"

        $userGroups = Get-ADPrincipalGroupMembership $userPrincipalName | Select-Object Name
        if ($userGroups) {
            Write-Host "$fullName is member of the following groups:"
            $userGroups | ForEach-Object {
                Write-Host "  - $($_.Name)"
            }
        } else {
            Write-Host "$fullName is not a member of any groups."
        }
    } else {
        Write-Host "User not found."
    }
}
function Build-OUTree($username, $depth = 0) {
    $user = Get-ADUser -Identity $username
    $userDN = $user.DistinguishedName
    $ouHierarchy = $userDN -split "," | ForEach-Object {
        $_ -replace "CN=", "" -replace "OU=", ""
    }
    
    $ouPath = ""
    $ouTree = @()
    
    for ($i = 0; $i -lt $depth; $i++) {
        $ouPath += "|   "
    }
    
    $ouTree += "$ouPath|-- " + $ouHierarchy[0]
    
    for ($i = 1; $i -lt $ouHierarchy.Count; $i++) {
        $ouPath += "|   "
        $ouTree += "$ouPath|-- " + $ouHierarchy[$i]
    }
    
    $ouTree
}

# Main program loop
while ($true) {
    Clear-Host
    Write-Host @"
    ___  ______          _____                           _     
    / _ \ |  _  \        /  ___|                         | |    
   / /_\ \| | | | ______ \ `--.   ___   __ _  _ __   ___ | |__  
   |  _  || | | ||______| `--. \ / _ \ / _` || '__| / __|| '_ \ 
   | | | || |/ /         /\__/ /|  __/| (_| || |   | (__ | | | |
   \_| |_/|___/          \____/  \___| \__,_||_|    \___||_| |_|
   
   v. 0.6.5 @ Scope edition by Claus Malver                                                                                                                                                 
                                               

AD-Search - Active Directory
Available Commands:
1. Search for username
2. Search for a group
3. List groups a specific user is a member of
4. List members of a group
5. Full report on an user
6. Get a small report on your current user
7. Get a "tree" structure of what OU's a user is a member of
0. Exit
"@

    $choice = Read-Host "Enter a command (1-8):"

    switch ($choice) {
        '1' {
            $username = Read-Host "Enter the username:"
            Search-User $username
        }
        '2' {
            $groupname = Read-Host "Enter the group name:"
            Search-Group $groupname
        }
        '3' {
            $username = Read-Host "Enter the username:"
            Get-UserGroupsList $username
        }
        '4' {
            $groupname = Read-Host "Enter the group name:"
            Get-GroupMemberslist $groupname
        }
        '5' {
            $groupname = Read-Host "Enter the username for a full report:"
            Get-UserReport $groupname
        }
        '6' {
            Get-MyUserInfo
        }
        '7' {
            $username = Read-Host "Enter the username for OU tree structure:"
            $ouTree = Build-OUTree $username
        
            Write-Host "OU Tree Structure for User: $username"
            $ouTree | ForEach-Object {
                Write-Host $_
            }
        }
        '0' {
            exit
        }
        default {
            Write-Host "Invalid command. Try again."
        }
    }
}
