## Name: ChangePasswordNextLogon.ps1
## Author: 
##          brian@sfti.in
## Purpose:
##          To set "Change Password at next logon" bit for compromised users in bulk from a provided email list.
## Inputs:
##          List of affected users in CSV format
## Ouputs:
##          basic Logfile with action details

# Take Command Line Arguments for the Script
param (
    [Parameter(Mandatory=$true)][string]$InputFile,
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,
    $logfile = ".\PasswordChangesLog.log",
    $V = $FALSE
 )

# Import Affected Users emails in CSV Email, Breach format
$EmailList = Import-Csv -Path $InputFile -Header @("Email", "Breach")

foreach($line in $EmailList){
    try{
        # Take Email from CSV line
        $uEmail = $line.Email
        if($V){Write-Host "Last User = " $uEmail}    # Writes Debug Information to Screen when debug flag is set to true
        
        # Find User in AD from their Email and Create AD User object for use later
        $AD_User = Get-ADUser -Filter "EmailAddress -eq '$uEmail'" -Properties EmailAddress -ErrorAction Stop
        if($V){Write-Host "Search Exit Code = " $?}

        # Set the Change Password At Next Logon Bit for our new AD user object
        Set-ADUser -Identity $AD_User -ChangePasswordAtLogon $true -Credential $Credential -ErrorAction Stop
        if($V){Write-Host "Change Exit Code = " $?}

        # Pull out the AD User object name for use in log file entry and write information to log
        $name = $AD_User.UserPrincipalName
        Add-Content -Path $logfile "$name's Logon Password Requirement is Set!"
    }
    # Handle Verious kind of errors including bad credentials, log file access, and unkown errors
    catch [System.Security.Authentication.AuthenticationException]{
        Write-Host "Error: Supplied Credentials are rejected by the AD server - No movements can be made"
        Write-Host "Execution Terminated"
        exit
    }
    catch [GetContentWriterIOError]{
        Write-Host "Error: Could not write to log file - continuing with out log"
    }
    catch{
        Write-Host "Error: Unhandled Error Occured! Attemtping to continue"
        Add-Content -Path $logfile "Error: Unhandled Error Occured! Attemtping to continue"
    }
    
}

# Script Clean up and Conclusion Notice
Add-Content -Path $logfile "Changes Compleated"
Write-Host "Changes are compeated, provided users must change password next time they log in"


