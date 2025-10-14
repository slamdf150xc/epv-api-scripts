[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidatePattern('\.csv$')]
    [Alias("Report")]
    [String]$ReportPath = ".\SafeMemberReport.csv",

    [Parameter(Mandatory = $false)]
    [array]$UserTypes = @("EPVUser", "BasicUser"),

    [Parameter(Mandatory = $false)]
    [Switch]$ExcludeUsers,
    
    [Parameter(Mandatory = $false)]
    [Switch]$IncludePredefinedUsers,

    [Parameter(Mandatory = $false)]
    [Switch]$IncludeGroups,

    [Parameter(Mandatory = $false)]
    [Switch]$IncludeApps,

    [Parameter(Mandatory = $false)]
    [Switch]$HidePerms,

    [Parameter(Mandatory = $false)]
    $PermList,

    [Parameter(Mandatory = $false)]
    $logonToken,

    [Parameter(Mandatory = $false)]
    [String]$IdentityUserName,

    [Parameter(Mandatory = $false)]
    [String]$IdentityURL,

    [Parameter(Mandatory = $false)]
    [String]$PCloudSubDomain,

    [Parameter(Mandatory = $false)]
    [String]$PVWAAddress,

    [Parameter(Mandatory = $false)]
    [PSCredential]$PVWACredentials,

    [Parameter(Mandatory = $false)]
    [String]$PVWAAuthType = "CyberArk"
)

function Log {
    param(
        [string]$Msg,
        [ValidateSet("INFO","SUCCESS","WARNING","ERROR","FATAL")]
        [string]$Level = "INFO",
        [bool]$NoNewLine = $false
    )
    switch ($Level) {
        "INFO"    { $color = "White" }
        "SUCCESS" { $color = "Green" }
        "WARNING" { $color = "Yellow" }
        "ERROR"   { $color = "Red" }
        "FATAL"   { $color = "Magenta" }        
        default   { $color = "Gray" }
    }
    if ($NoNewLine) {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Msg" -ForegroundColor $color -NoNewline
    } else {
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Msg" -ForegroundColor $color
    }
}

Log "Checking for PSPAS module..." "INFO" $true
if (!(Get-Module -ListAvailable -Name PSPAS)) {
    try {
        Write-Host ""
        Install-Module PSPAS -Scope CurrentUser -Force
        Log "PSPAS module installed successfully." "SUCCESS"
    } catch {
        Write-Host ""
        Log "PSPAS module not found and could not be installed. Please install manually." "ERROR"
        exit
    }
} else {
    Write-Host "Done" -ForegroundColor Green
}

Get-PASComponentSummary -ErrorAction SilentlyContinue -ErrorVariable TestConnect | Out-Null
if ($TestConnect.Count -ne 0) {
    Close-PASSession -ErrorAction SilentlyContinue
}

If ($null -eq (Get-PASSession).User) {
    if (![string]::IsNullOrEmpty($logonToken)) {
        Log "Using provided logon token..." "INFO"
        Use-PASSession $logonToken
    } elseif (![string]::IsNullOrEmpty($IdentityUserName)) {
        Log "Performing Identity-based authentication..." "INFO"
        if (!(Test-Path .\IdentityAuth.psm1)) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cyberark/epv-api-scripts/main/Identity%20Authentication/IdentityAuth.psm1" -OutFile "IdentityAuth.psm1"
        }
        Import-Module .\IdentityAuth.psm1
        $header = Get-IdentityHeader -psPASFormat -IdentityTenantURL $IdentityURL -IdentityUserName $IdentityUserName -PCloudTenantAPIURL "https://$PCloudSubDomain.privilegecloud.cyberark.cloud/passwordvault/"
        if ($null -eq $header) {
            Log "Identity authentication failed." "ERROR"
            exit
        }
        Use-PASSession $header
        Log "Successfully connected via Identity." "SUCCESS"
    } elseif (![string]::IsNullOrEmpty($PVWAAddress)) {
        if ([string]::IsNullOrEmpty($PVWACredentials)) {
            $PVWACredentials = Get-Credential
        }
        Log "Connecting to PVWA..." "INFO" $true
        New-PASSession -Credential $PVWACredentials -ConcurrentSession $true -BaseURI $PVWAAddress -Type $PVWAAuthType
        Write-Host "Done" -ForegroundColor Green
    } else {
        Log "No connection parameters provided. Please specify logonToken, PVWAAddress, or IdentityURL/SubDomain." "ERROR"
        exit
    }
}

if (!$ExcludeUsers) {
    $IncludedUsersTypes = $UserTypes
}
if ($IncludeApps) {
    $IncludedUsersTypes = @("AppProvider", "AIMAccount") + $IncludedUsersTypes
}

Log "Retrieving Safes..." "INFO" $true
$Safes = Get-PASSafe
[hashtable]$safesht = @{ }
$Safes | ForEach-Object { $safesht.Add($_.SafeName, $_) }
Write-Host "Done" -ForegroundColor Green

Log "Retrieving Users..." "INFO" $true
$Users = Get-PASUser
[hashtable]$Usersht = @{ }
$Users | ForEach-Object { $Usersht.Add($_.UserName, $_) }
Write-Host "Done" -ForegroundColor Green

Log "Retrieving Safe Members..." "INFO" $true
$SafeMembers = $Safes | Get-PASSafeMember -IncludePredefinedUsers $IncludePredefinedUsers -ErrorAction SilentlyContinue
$SafeMembers | Add-Member -MemberType NoteProperty -Name UserInfo -Value $null -Force
$SafeMembers | Add-Member -MemberType NoteProperty -Name SafeInfo -Value $null -Force
$SafeMembers | ForEach-Object { $_.UserInfo = $Usersht[$_.UserName] }
$SafeMembers | ForEach-Object { $_.SafeInfo = $safesht[$_.SafeName] }
Write-Host "Done" -ForegroundColor Green

if ($IncludeGroups) {
    $SafeMembersList = $SafeMembers | Where-Object { ($_.UserInfo.UserType -in $IncludedUsersTypes) -or ($_.MemberType -eq "Group") }
} else {
    $SafeMembersList = $SafeMembers | Where-Object { $_.UserInfo.UserType -in $IncludedUsersTypes }
}

if (-not $SafeMembersList -or $SafeMembersList.Count -eq 0) {
    Log 'No safe members found — expand search parameters and try again.' WARNING
    return
}

$props = @("Source", "UserType", "Description", "ManagingCPM", "NumberOfDaysRetention", "NumberOfVersionsRetention")
$props | ForEach-Object { $SafeMembersList | Add-Member -MemberType NoteProperty -Name $_ -Value $null -Force }

Log "Processing Safe Members..." "INFO" $true
$SafeMembersList | ForEach-Object {    
    try {
        $_.Source = $_.UserInfo.Source
        $_.UserType = $_.UserInfo.UserType
        $_.ManagingCPM = $_.SafeInfo.ManagingCPM
        $_.Description = $_.SafeInfo.Description
        $_.NumberOfDaysRetention = $_.SafeInfo.NumberOfDaysRetention
        $_.NumberOfVersionsRetention = $_.SafeInfo.NumberOfVersionsRetention        
    } catch {
        Write-Host""
        Log "$($_.Exception.Message)" "ERROR"
    }
}
Write-Host "Done" -ForegroundColor Green

Log "Expanding Group Members..." "INFO" $true
$ExpandedGroupMembers = @()
foreach ($groupMember in $SafeMembersList | Where-Object { $_.MemberType -eq "Group" }) {
    try {
        $groupUsers = Get-PASGroup -id $groupMember.memberId -includeMembers $true -ErrorAction SilentlyContinue
        foreach ($user in $groupUsers.members) {
            if (!$groupMember.memberType -eq "Group") {
                $UserInfo = Get-PASUser -id $user.id
            }
            $expanded = [PSCustomObject]@{
                Username   = $user.username
                Source     = $UserInfo.source
                MemberType = $UserInfo.userType
                UserType   = $user.UserType
                SafeName   = $groupMember.SafeName
                Description = $groupMember.SafeInfo.Description
                ManagingCPM = $groupMember.SafeInfo.ManagingCPM
                NumberOfDaysRetention = $groupMember.SafeInfo.NumberOfDaysRetention
                NumberOfVersionsRetention = $groupMember.SafeInfo.NumberOfVersionsRetention
                Permissions = $groupMember.Permissions
            }
            $ExpandedGroupMembers += $expanded
        }
        #Log "Expanded group '$($groupMember.UserName)' in Safe '$($groupMember.SafeName)'" "SUCCESS"
    } catch {
        Write-Host ""
        Log "Failed to expand group '$($groupMember.UserName)' in Safe '$($groupMember.SafeName)'" "WARNING"
    }
}
Write-Host "Done" -ForegroundColor Green

$SafeMembersList += $ExpandedGroupMembers

[array]$ReportProps = @("Username", "Source", "MemberType", "UserType", "SafeName", "Description", "ManagingCPM", "NumberOfDaysRetention", "NumberOfVersionsRetention")

if (-not $HidePerms) {
    if ($PermList) {
        Log "Collecting permission properties..." "INFO" $true
        $permProps = $SafeMembersList |
            ForEach-Object { $_.Permissions.PSObject.Properties.Name } |
            Select-Object -Unique |
            Where-Object { $_ -is [string] -and $_ -notin $ReportProps }
        Write-Host "Done" -ForegroundColor Green
        [array]$outputProps = $ReportProps + $permProps
    } else {
        [array]$outputProps = $ReportProps + $PermList
    }
} else {
    [array]$outputProps = $ReportProps
}

Write-Host "`nExporting the following columns to CSV:" -ForegroundColor Cyan
$outputProps | ForEach-Object { Write-Host " - $_" }

Log "Exporting Safe Member data to $ReportPath..." INFO $true
try {
    $exportData = @()
    foreach ($member in $SafeMembersList) {
        $obj = @{}
        foreach ($prop in $ReportProps) {
            $obj[$prop] = $member.$prop
        }
        if ($member.Permissions -and $member.Permissions.PSObject.Properties.Count -gt 0) {
            foreach ($perm in $member.Permissions.PSObject.Properties) {
                $obj[$perm.Name] = "$($perm.Value)"
            }
        }
        $exportData += [PSCustomObject]$obj
    }

    $validProps = @()
    foreach ($prop in $outputProps) {
        if ($exportData[0].PSObject.Properties.Name -contains $prop) {
            $validProps += $prop
        } else {
            Write-Host ""
            Log "Property '$prop' not found in export data" WARNING
        }
    }

    $exportData |
        Select-Object -Property $validProps |
        Sort-Object -Property Username, SafeName |
        Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

    Write-Host "Done" -ForegroundColor Green
    Log "Report saved to $ReportPath" "SUCCESS"
} catch {
    Log "Failed to export CSV: $($_.Exception.Message)" "ERROR"
}

Log "=== Script completed successfully ===" "SUCCESS"
