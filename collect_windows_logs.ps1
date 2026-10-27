
$ErrorActionPreference = "Stop"

$folder = Split-Path -Parent $MyInvocation.MyCommand.Path
$outputFile = Join-Path $folder "security_log.txt"

try {
    # Read recent Windows successful and failed logon events
    $events = @(
        Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            Id = @(4624, 4625)
        } -MaxEvents 500
    )

    $rows = foreach ($logEvent in $events) {
        [xml]$xml = $logEvent.ToXml()
        $fields = @{}

        foreach ($item in $xml.Event.EventData.Data) {
            $fields[[string]$item.Name] = [string]$item.'#text'
        }

        $logonType = $fields["LogonType"]
        $ip = $fields["IpAddress"]
        $username = $fields["TargetUserName"]

        if ([string]::IsNullOrWhiteSpace($username)) {
            $username = "Unknown"
        }

        if ([string]::IsNullOrWhiteSpace($ip)) {
            $ip = "-"
        }

        # Skip service logons and other non-interactive successes.
        # Keep failed logons because they can be important.
        if ($logEvent.Id -eq 4624 -and $logonType -notin @("2", "3", "10", "11")) {
            continue
        }

        if ($logEvent.Id -eq 4624) {
            $level = "INFO"
            $kind = "LOGIN_SUCCESS"
        }
        else {
            $level = "WARNING"
            $kind = "LOGIN_FAILED"
        }

        [PSCustomObject]@{
            Timestamp = $logEvent.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Level = $level
            IP = $ip
            Event = $kind
            Username = $username
        }
    }

    # Write dashboard-compatible CSV rows
    $csvRows = @(
        $rows |
        Select-Object Timestamp, Level, IP, Event, Username |
        ConvertTo-Csv -NoTypeInformation |
        Select-Object -Skip 1
    )

    if ($csvRows.Count -gt 0) {
        Set-Content -Path $outputFile -Value $csvRows -Encoding UTF8
        Write-Host "Collected $($csvRows.Count) log entries."
    }
    else {
        Set-Content -Path $outputFile -Value "" -Encoding UTF8
        Write-Host "No matching logon events found."
    }

    Write-Host "Saved to: $outputFile"
}
catch {
    Write-Host "Could not read Windows Security logs."
    Write-Host $_.Exception.Message
    Write-Host "Run PowerShell as Administrator and check audit settings."
}
