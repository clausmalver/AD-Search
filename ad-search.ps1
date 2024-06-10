<#
.SYNOPSIS
A script to use as a daily driver when troubleshooting or engaging with users during support.

.DESCRIPTION
This script is designed to assist in daily support tasks and troubleshooting by retrieving and displaying information about users or groups from Active Directory. It uses the "ActiveDirectory" module from RSAT Tools and its cmdlets to perform these tasks.

The script can retrieve details such as user names, group memberships, and other relevant attributes. It can also perform searches based on various criteria, making it a versatile tool for support and troubleshooting tasks.

Please note that this script requires the "ActiveDirectory" module to be installed and available.

More detailed information can be found at https://github.com/clausmalver/AD-Search

Thanks!

.NOTES
Script Name: ad_search.ps1
Author: Claus Malver
Version: 0.6.5
Last Modified: 2024-06-10
#>

# Import the ActiveDirectory module
Import-Module ActiveDirectory

# Function to search for a user
function Search-User {
    param (
        [string]$username
    )

    try {
        $user = Get-ADUser -Filter {SamAccountName -eq $username} -Properties DisplayName,LastLogon,WhenCreated,Enabled,UserPrincipalName,EmailAddress,LockedOut,Manager,BadLogonCount

        if ($user) {
            $displayName = $user.DisplayName
            $emailAddress = $user.EmailAddress
            $lastLogon = [DateTime]::FromFileTime($user.LastLogon)
            $creationDate = $user.WhenCreated
            $accountStatus = if ($user.Enabled) { "Enabled" } else { "Disabled" }
            $lockedOut = if ($user.LockedOut) { "Locked Out" } else { "Not Locked Out" }
            $badLogonCount = $user.BadLogonCount
            $manager = Get-ADUser -Identity $user.Manager -Properties DisplayName | Select-Object -ExpandProperty DisplayName

            $result = @{
                'User'                = $displayName
                'Email Address'       = $emailAddress
                'Last Active'         = $lastLogon
                'Created'             = $creationDate
                'Account Status'      = $accountStatus
                'Locked Out Status'   = $lockedOut
                'Failed Logon Attempts' = $badLogonCount
                'Manager'             = $manager
            }

            $result | Format-Table -AutoSize
        } else {
            Write-Host "User not found."
        }
    } catch {
        Write-Host "An error occurred while searching for the user: $_"
    }
}
# Function to search for a group
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
            Write-Host "Description: $description"
            Write-Host "GUID: $guid"
        } else {
            Write-Host "Group not found."
        }
    } catch {
        Write-Host "An error occurred while searching for the group: $_"
    }
}
# Function get user group memberships
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

            $userGroups = $userGroups | Sort-Object 'Group Name'  # Sort the groups alphabetically
            $userGroups | Format-Table -AutoSize
        } else {
            Write-Host "User not found."
        }
    } catch {
        Write-Host "An error occurred while listing the user's groups: $_"
    }
}
# Function to get group members
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
# Function to get members of a specific office location
# Function to get members of a specific office location whose usernames start with "N1"
function Get-OfficeLocationMembersList {
    param (
        [string]$officeLocation
    )

    try {
        # Retrieve users based on office location
        $users = Get-ADUser -Filter {Office -eq $officeLocation} -Property SamAccountName, DisplayName, EmailAddress

        if ($users) {
            # Filter users whose usernames start with "N1"
            $filteredUsers = $users | Where-Object { $_.SamAccountName -like "N1*" }

            if ($filteredUsers) {
                $members = $filteredUsers | ForEach-Object {
                    [PSCustomObject]@{
                        'Username'  = $_.SamAccountName
                        'Full Name' = $_.DisplayName
                        'Email'     = $_.EmailAddress
                    }
                }

                $members | Format-Table -AutoSize
            } else {
                Write-Host "No users found with usernames starting with 'N1' in the specified office location."
            }
        } else {
            Write-Host "No users found for the specified office location."
        }
    } catch {
        Write-Host "An error occurred while listing office location members: $_"
    }
}

# Function to create a report for a user
function Get-UserReport {
    param (
        [string]$username
    )

    try {
        $user = Get-ADUser -Filter {SamAccountName -eq $username} -Properties DisplayName, SamAccountName, Manager, LastLogon, WhenCreated, Enabled, LockedOut, PasswordLastSet, badPwdCount, Office, Department, Company, StreetAddress, City, OfficePhone, otherMobile

        if ($user) {
            $manager = Get-ADUser -Identity $user.Manager -Properties DisplayName | Select-Object -ExpandProperty DisplayName

            $lastLogon = [DateTime]::FromFileTime($user.LastLogon).ToString("yyyy-MM-dd HH:mm:ss")

            $userReport = @{
                'User'                = $user.DisplayName
                'SAM Account Name'     = $user.SamAccountName
                'Manager'             = $manager
                'Office'              = $user.Office
                'Department'          = $user.Department
                'Company'             = $user.Company
                'Address'             = "$($user.StreetAddress), $($user.City)"
                'Phone'               = "$($user.OfficePhone), $($user.otherMobile)"
                'Created'             = $user.WhenCreated
                'Account Status'      = if ($user.Enabled) { "Enabled" } else { "Disabled" }
                'Locked Out Status'   = if ($user.LockedOut) { "Yes" } else { "No" }
                'Last Active'         = $lastLogon
                'Password Last Set'   = $user.PasswordLastSet
                'Bad Password Count'   = $user.badPwdCount
            }

            $userReport | Format-Table -AutoSize
        } else {
            Write-Host "User not found."
        }
    } catch {
        Write-Host "An error occurred while generating the user report: $_"
    }
}

# Main program loop
$continue = $true

while ($continue) {
    Clear-Host
    Write-Host @"
          _____         _____                     _     
    /\   |  __ \       / ____|                   | |    
   /  \  | |  | |_____| (___   ___  __ _ _ __ ___| |__  
  / /\ \ | |  | |______\___ \ / _ \/ _`  | '__/ __| '_ \ 
 / ____ \| |__| |      ____) |  __/ (_| | | | (__| | | |
/_/    \_\_____/      |_____/ \___|\__,_|_|  \___|_| |_|
                                                                                                
version 0.6.5 @ Scope edition by Claus Malver                                                                                                                                                 
                                                                                                                                                
AD-Search - Active Directory

Available Commands:
1. Search for a user
2. Search for a group
3. Search for a user groupmemberships
4. Search for members of a group
5. Search for members of an Office Location
6. Create a report for a user

0. Exit
"@

    $choice = Read-Host "Enter a command (1-6) or 0 to exit"
    switch ($choice) {
        '1' {
            $username = Read-Host "Enter the username"
            Search-User $username
            Read-Host "Press Enter to continue..."
        }

        '2' {
            $groupname = Read-Host "Enter the name of the group"
            Search-Group $groupname
            Read-Host "Press Enter to continue..."
        }
        '3' {
            $username = Read-Host "Enter the username"
            Get-UserGroupsList $username
            Read-Host "Press Enter to continue..."
        }
        '4' {
            $groupname = Read-Host "Enter the name of the group"
            Get-GroupMemberslist $groupname
            Read-Host "Press Enter to continue..."
        }
        '5' {
            $officeLocation = Read-Host "Enter the name of the Office Location"
            Get-OfficeLocationMembersList $officeLocation
            Read-Host "Press Enter to continue..."
        }
        '6' {
            $username = Read-Host "Enter the name of the user"
            Get-UserReport $username
            Read-Host "Press Enter to continue..."
        }

        '0' {
            $continue = $false  # Exit the loop
        }

        default {
            Write-Host "Invalid command. Try again."
        }
    }
}
