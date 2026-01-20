<#
.SYNOPSIS
    VDI Patch Manager - Automatic software updates from network file shares
    
.DESCRIPTION
    Runs at Windows startup to check file shares for application updates.
    Installs newer versions silently with comprehensive logging and retry logic.
    Supports prod/non-prod file share fallback with network segmentation awareness.
    
.NOTES
    Author: Generated for AWS Workspaces VDI Management
    Version: 1.0
    Log Location: C:\temp\VDIupdates\log.txt
    Version Registry: C:\temp\VDIupdates\versions.json
#>

#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION SECTION - CUSTOMIZE THESE VALUES
# ============================================================================

$Global:Config = @{
    # File Share Locations (UNC paths)
    PrimaryShare   = "\\prod-fileserver\patches"
    FallbackShare  = "\\nonprod-fileserver\patches"
    
    # Local directories
    LogDir         = "C:\temp\VDIupdates"
    LogFile        = "C:\temp\VDIupdates\log.txt"
    VersionFile    = "C:\temp\VDIupdates\versions.json"
    TempDir        = "C:\temp\VDIupdates\installers"
    LockFile       = "C:\temp\VDIupdates\update.lock"
    
    # Retry settings
    MaxRetries     = 3
    RetryDelaySeconds = 30
    
    # Installation settings
    InstallTimeout = 600  # 10 minutes per installer
    CopyTimeout    = 300  # 5 minutes to copy from share
    
    # Supported applications and their silent install parameters
    Applications = @{
        "nodejs" = @{
            Pattern = "node-v*-x64.msi"
            VersionRegex = "node-v([0-9.]+)-x64\.msi"
            SilentArgs = "/qn /norestart"
            Installer = "msiexec.exe"
        }
        "git" = @{
            Pattern = "Git-*-64-bit.exe"
            VersionRegex = "Git-([0-9.]+)-64-bit\.exe"
            SilentArgs = "/VERYSILENT /NORESTART /SUPPRESSMSGBOXES"
            Installer = $null  # Uses the exe directly
        }
        "notepadpp" = @{
            Pattern = "npp.*.Installer.x64.exe"
            VersionRegex = "npp\.([0-9.]+)\.Installer\.x64\.exe"
            SilentArgs = "/S"
            Installer = $null
        }
        "winscp" = @{
            Pattern = "WinSCP-*-Setup.exe"
            VersionRegex = "WinSCP-([0-9.]+)-Setup\.exe"
            SilentArgs = "/VERYSILENT /NORESTART"
            Installer = $null
        }
        "filezilla" = @{
            Pattern = "FileZilla_*_win64-setup.exe"
            VersionRegex = "FileZilla_([0-9.]+)_win64-setup\.exe"
            SilentArgs = "/S"
            Installer = $null
        }
        "wireshark" = @{
            Pattern = "Wireshark-win64-*.exe"
            VersionRegex = "Wireshark-win64-([0-9.]+)\.exe"
            SilentArgs = "/S /desktopicon=no /quicklaunchicon=no"
            Installer = $null
        }
        "tomcat9" = @{
            Pattern = "apache-tomcat-9.*.zip"
            VersionRegex = "apache-tomcat-(9\.[0-9.]+)\.zip"
            SilentArgs = $null  # ZIP extraction only
            Installer = "ZIP"
        }
        "tomcat10" = @{
            Pattern = "apache-tomcat-10.*.zip"
            VersionRegex = "apache-tomcat-(10\.[0-9.]+)\.zip"
            SilentArgs = $null
            Installer = "ZIP"
        }
        "intellij-community" = @{
            Pattern = "ideaIC-*.exe"
            VersionRegex = "ideaIC-([0-9.]+)\.exe"
            SilentArgs = "/S /CONFIG=C:\temp\VDIupdates\silent.config /D=C:\Program Files\JetBrains\IntelliJ IDEA Community Edition"
            Installer = $null
        }
        "intellij-ultimate" = @{
            Pattern = "ideaIU-*.exe"
            VersionRegex = "ideaIU-([0-9.]+)\.exe"
            SilentArgs = "/S /CONFIG=C:\temp\VDIupdates\silent.config /D=C:\Program Files\JetBrains\IntelliJ IDEA Ultimate Edition"
            Installer = $null
        }
    }
}

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Initialize-Logging {
    <#
    .SYNOPSIS
        Creates log directory and initializes log file
    #>
    try {
        if (-not (Test-Path $Global:Config.LogDir)) {
            New-Item -Path $Global:Config.LogDir -ItemType Directory -Force | Out-Null
            Write-Host "[INIT] Created log directory: $($Global:Config.LogDir)" -ForegroundColor Green
        }
        
        if (-not (Test-Path $Global:Config.TempDir)) {
            New-Item -Path $Global:Config.TempDir -ItemType Directory -Force | Out-Null
        }
        
        # Rotate log if it's too large (>10MB)
        if (Test-Path $Global:Config.LogFile) {
            $logSize = (Get-Item $Global:Config.LogFile).Length / 1MB
            if ($logSize -gt 10) {
                $archiveName = "log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                Move-Item -Path $Global:Config.LogFile -Destination (Join-Path $Global:Config.LogDir $archiveName)
                Write-Log "Rotated large log file to: $archiveName"
            }
        }
        
        Write-Log "========================================================================================================" -NoConsole
        Write-Log "VDI PATCH MANAGER - Session Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -NoConsole
        Write-Log "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -NoConsole
        Write-Log "========================================================================================================" -NoConsole
        
    } catch {
        Write-Host "[ERROR] Failed to initialize logging: $_" -ForegroundColor Red
        throw
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes timestamped message to log file and console
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',
        
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to file
    try {
        Add-Content -Path $Global:Config.LogFile -Value $logMessage -ErrorAction Stop
    } catch {
        Write-Host "[ERROR] Cannot write to log file: $_" -ForegroundColor Red
    }
    
    # Write to console with color coding
    if (-not $NoConsole) {
        $color = switch ($Level) {
            'SUCCESS' { 'Green' }
            'WARNING' { 'Yellow' }
            'ERROR'   { 'Red' }
            'DEBUG'   { 'Cyan' }
            default   { 'White' }
        }
        Write-Host $logMessage -ForegroundColor $color
    }
}

# ============================================================================
# LOCK FILE MANAGEMENT
# ============================================================================

function Test-UpdateLock {
    <#
    .SYNOPSIS
        Checks if another update process is running
    #>
    if (Test-Path $Global:Config.LockFile) {
        $lockContent = Get-Content $Global:Config.LockFile -Raw | ConvertFrom-Json
        $lockPID = $lockContent.PID
        
        # Check if process is still running
        $process = Get-Process -Id $lockPID -ErrorAction SilentlyContinue
        if ($process) {
            $lockAge = (Get-Date) - $lockContent.Timestamp
            if ($lockAge.TotalMinutes -gt 60) {
                Write-Log "Lock file is stale (>60 minutes), removing" -Level WARNING
                Remove-Item $Global:Config.LockFile -Force
                return $false
            }
            Write-Log "Another update process is running (PID: $lockPID)" -Level WARNING
            return $true
        } else {
            Write-Log "Stale lock file detected, removing" -Level WARNING
            Remove-Item $Global:Config.LockFile -Force
            return $false
        }
    }
    return $false
}

function Set-UpdateLock {
    <#
    .SYNOPSIS
        Creates lock file to prevent concurrent runs
    #>
    $lockData = @{
        PID = $PID
        Timestamp = Get-Date
        Computer = $env:COMPUTERNAME
    } | ConvertTo-Json
    
    Set-Content -Path $Global:Config.LockFile -Value $lockData
    Write-Log "Lock file created (PID: $PID)" -Level DEBUG
}

function Remove-UpdateLock {
    <#
    .SYNOPSIS
        Removes lock file when update process completes
    #>
    if (Test-Path $Global:Config.LockFile) {
        Remove-Item $Global:Config.LockFile -Force
        Write-Log "Lock file removed" -Level DEBUG
    }
}

# ============================================================================
# VERSION MANAGEMENT
# ============================================================================

function Get-InstalledVersions {
    <#
    .SYNOPSIS
        Loads version registry from JSON file
    #>
    if (Test-Path $Global:Config.VersionFile) {
        try {
            $versions = Get-Content $Global:Config.VersionFile -Raw | ConvertFrom-Json
            Write-Log "Loaded version registry: $($versions.PSObject.Properties.Count) applications tracked" -Level DEBUG
            return $versions
        } catch {
            Write-Log "Failed to parse version file, starting fresh: $_" -Level WARNING
            return @{}
        }
    } else {
        Write-Log "No existing version registry found, starting fresh" -Level DEBUG
        return @{}
    }
}

function Save-InstalledVersions {
    <#
    .SYNOPSIS
        Saves version registry to JSON file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Versions
    )
    
    try {
        $json = $Versions | ConvertTo-Json -Depth 10
        Set-Content -Path $Global:Config.VersionFile -Value $json
        Write-Log "Version registry saved successfully" -Level DEBUG
    } catch {
        Write-Log "Failed to save version registry: $_" -Level ERROR
    }
}

function Compare-Versions {
    <#
    .SYNOPSIS
        Compares two version strings (e.g., "1.2.3" vs "1.2.4")
    #>
    param(
        [string]$Version1,
        [string]$Version2
    )
    
    if ([string]::IsNullOrEmpty($Version1)) { return $true }
    if ([string]::IsNullOrEmpty($Version2)) { return $false }
    
    try {
        $v1 = [version]$Version1
        $v2 = [version]$Version2
        return $v2 -gt $v1
    } catch {
        # Fallback to string comparison if version parsing fails
        return $Version2 -ne $Version1
    }
}

# ============================================================================
# NETWORK SHARE FUNCTIONS
# ============================================================================

function Test-FileShare {
    <#
    .SYNOPSIS
        Tests connectivity to a network file share
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SharePath
    )
    
    Write-Log "Testing connectivity to: $SharePath" -Level DEBUG
    
    try {
        if (Test-Path $SharePath -ErrorAction Stop) {
            Write-Log "✓ Successfully connected to: $SharePath" -Level SUCCESS
            return $true
        } else {
            Write-Log "✗ Cannot access share: $SharePath" -Level WARNING
            return $false
        }
    } catch {
        Write-Log "✗ Error testing share $SharePath : $_" -Level WARNING
        return $false
    }
}

function Get-AvailableFileShare {
    <#
    .SYNOPSIS
        Determines which file share is accessible (prod vs non-prod)
    #>
    Write-Log "Determining accessible file share..." -Level INFO
    
    if (Test-FileShare -SharePath $Global:Config.PrimaryShare) {
        Write-Log "Using PRIMARY share: $($Global:Config.PrimaryShare)" -Level SUCCESS
        return $Global:Config.PrimaryShare
    } elseif (Test-FileShare -SharePath $Global:Config.FallbackShare) {
        Write-Log "Using FALLBACK share: $($Global:Config.FallbackShare)" -Level SUCCESS
        return $Global:Config.FallbackShare
    } else {
        Write-Log "No accessible file shares found!" -Level ERROR
        return $null
    }
}

# ============================================================================
# APPLICATION DISCOVERY
# ============================================================================

function Find-ApplicationsOnShare {
    <#
    .SYNOPSIS
        Scans file share for available application installers
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SharePath
    )
    
    Write-Log "Scanning file share for application installers..." -Level INFO
    $foundApps = @{}
    
    foreach ($appName in $Global:Config.Applications.Keys) {
        $appConfig = $Global:Config.Applications[$appName]
        $pattern = $appConfig.Pattern
        
        Write-Log "  → Searching for: $appName ($pattern)" -Level DEBUG
        
        try {
            $files = Get-ChildItem -Path $SharePath -Filter $pattern -File -ErrorAction Stop
            
            if ($files) {
                # Get the newest file if multiple versions exist
                $newestFile = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                
                # Extract version from filename
                if ($newestFile.Name -match $appConfig.VersionRegex) {
                    $version = $matches[1]
                    
                    $foundApps[$appName] = @{
                        FileName = $newestFile.Name
                        FullPath = $newestFile.FullName
                        Version = $version
                        Size = $newestFile.Length
                        Modified = $newestFile.LastWriteTime
                    }
                    
                    Write-Log "    ✓ Found: $($newestFile.Name) [v$version]" -Level SUCCESS
                } else {
                    Write-Log "    ✗ Found file but could not extract version: $($newestFile.Name)" -Level WARNING
                }
            } else {
                Write-Log "    - Not found: $appName" -Level DEBUG
            }
        } catch {
            Write-Log "    ✗ Error searching for $appName : $_" -Level ERROR
        }
    }
    
    Write-Log "Discovery complete: Found $($foundApps.Count) applications" -Level INFO
    return $foundApps
}

# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================

function Copy-InstallerFromShare {
    <#
    .SYNOPSIS
        Copies installer from file share to local temp directory
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )
    
    Write-Log "Copying installer from share..." -Level INFO
    Write-Log "  Source: $SourcePath" -Level DEBUG
    Write-Log "  Destination: $DestinationPath" -Level DEBUG
    
    try {
        $copyJob = Start-Job -ScriptBlock {
            param($src, $dst)
            Copy-Item -Path $src -Destination $dst -Force
        } -ArgumentList $SourcePath, $DestinationPath
        
        $timeout = $Global:Config.CopyTimeout
        $completed = Wait-Job -Job $copyJob -Timeout $timeout
        
        if ($completed) {
            Receive-Job -Job $copyJob
            Remove-Job -Job $copyJob
            
            if (Test-Path $DestinationPath) {
                $fileSize = (Get-Item $DestinationPath).Length / 1MB
                Write-Log "  ✓ Copy successful: $([math]::Round($fileSize, 2)) MB" -Level SUCCESS
                return $true
            } else {
                Write-Log "  ✗ Copy failed: Destination file not found" -Level ERROR
                return $false
            }
        } else {
            Stop-Job -Job $copyJob
            Remove-Job -Job $copyJob
            Write-Log "  ✗ Copy timed out after $timeout seconds" -Level ERROR
            return $false
        }
    } catch {
        Write-Log "  ✗ Copy error: $_" -Level ERROR
        return $false
    }
}

function Install-Application {
    <#
    .SYNOPSIS
        Installs an application silently with retry logic
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppName,
        
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath,
        
        [Parameter(Mandatory=$true)]
        [string]$Version
    )
    
    $appConfig = $Global:Config.Applications[$AppName]
    $retryCount = 0
    $installed = $false
    
    while ($retryCount -le $Global:Config.MaxRetries -and -not $installed) {
        if ($retryCount -gt 0) {
            Write-Log "Retry attempt $retryCount of $($Global:Config.MaxRetries) for $AppName" -Level WARNING
            Start-Sleep -Seconds $Global:Config.RetryDelaySeconds
        }
        
        try {
            Write-Log "Installing $AppName v$Version (Attempt $($retryCount + 1))..." -Level INFO
            
            # Handle ZIP files differently
            if ($appConfig.Installer -eq "ZIP") {
                Write-Log "  → Extracting ZIP archive..." -Level INFO
                $extractPath = "C:\Program Files\$AppName-$Version"
                Expand-Archive -Path $InstallerPath -DestinationPath $extractPath -Force
                Write-Log "  ✓ Extracted to: $extractPath" -Level SUCCESS
                $installed = $true
            }
            # Handle MSI files
            elseif ($appConfig.Installer -eq "msiexec.exe") {
                $arguments = "/i `"$InstallerPath`" $($appConfig.SilentArgs) /L*V `"$($Global:Config.LogDir)\install_${AppName}_${Version}.log`""
                Write-Log "  → Running: msiexec.exe $arguments" -Level DEBUG
                
                $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru -NoNewWindow
                $exitCode = $process.ExitCode
                
                if ($exitCode -eq 0 -or $exitCode -eq 3010) {
                    Write-Log "  ✓ Installation successful (Exit Code: $exitCode)" -Level SUCCESS
                    $installed = $true
                } else {
                    Write-Log "  ✗ Installation failed (Exit Code: $exitCode)" -Level ERROR
                }
            }
            # Handle EXE installers
            else {
                $arguments = $appConfig.SilentArgs
                Write-Log "  → Running: $InstallerPath $arguments" -Level DEBUG
                
                $process = Start-Process -FilePath $InstallerPath -ArgumentList $arguments -Wait -PassThru -NoNewWindow
                $exitCode = $process.ExitCode
                
                if ($exitCode -eq 0) {
                    Write-Log "  ✓ Installation successful" -Level SUCCESS
                    $installed = $true
                } else {
                    Write-Log "  ✗ Installation failed (Exit Code: $exitCode)" -Level ERROR
                }
            }
            
        } catch {
            Write-Log "  ✗ Installation exception: $_" -Level ERROR
            Write-Log "  Stack trace: $($_.ScriptStackTrace)" -Level DEBUG
        }
        
        $retryCount++
    }
    
    if (-not $installed) {
        Write-Log "Failed to install $AppName after $($Global:Config.MaxRetries) retries" -Level ERROR
    }
    
    return $installed
}

# ============================================================================
# MAIN WORKFLOW
# ============================================================================

function Start-VDIUpdateProcess {
    <#
    .SYNOPSIS
        Main orchestration function
    #>
    
    try {
        Write-Log "============================================================" -Level INFO
        Write-Log "STARTING VDI UPDATE PROCESS" -Level INFO
        Write-Log "============================================================" -Level INFO
        
        # Check for existing lock
        if (Test-UpdateLock) {
            Write-Log "Update process already running, exiting" -Level WARNING
            return
        }
        
        # Create lock file
        Set-UpdateLock
        
        # Load installed versions
        $installedVersions = Get-InstalledVersions
        
        # Find accessible file share
        $fileShare = Get-AvailableFileShare
        if (-not $fileShare) {
            Write-Log "Cannot proceed without accessible file share" -Level ERROR
            return
        }
        
        # Discover applications on share
        $availableApps = Find-ApplicationsOnShare -SharePath $fileShare
        
        if ($availableApps.Count -eq 0) {
            Write-Log "No applications found on file share" -Level WARNING
            return
        }
        
        # Compare versions and build update list
        $updatesNeeded = @{}
        foreach ($appName in $availableApps.Keys) {
            $availableVersion = $availableApps[$appName].Version
            $installedVersion = $installedVersions.$appName
            
            if (Compare-Versions -Version1 $installedVersion -Version2 $availableVersion) {
                $updatesNeeded[$appName] = $availableApps[$appName]
                Write-Log "UPDATE NEEDED: $appName [$installedVersion → $availableVersion]" -Level INFO
            } else {
                Write-Log "UP-TO-DATE: $appName [v$installedVersion]" -Level SUCCESS
            }
        }
        
        if ($updatesNeeded.Count -eq 0) {
            Write-Log "All applications are up-to-date!" -Level SUCCESS
            return
        }
        
        Write-Log "============================================================" -Level INFO
        Write-Log "BEGINNING INSTALLATIONS ($($updatesNeeded.Count) updates)" -Level INFO
        Write-Log "============================================================" -Level INFO
        
        # Process each update
        $successCount = 0
        $failCount = 0
        
        foreach ($appName in $updatesNeeded.Keys) {
            $appInfo = $updatesNeeded[$appName]
            $version = $appInfo.Version
            
            Write-Log "" -Level INFO
            Write-Log "-----------------------------------------------------------" -Level INFO
            Write-Log "Processing: $appName v$version" -Level INFO
            Write-Log "-----------------------------------------------------------" -Level INFO
            
            # Copy installer to local temp
            $localPath = Join-Path $Global:Config.TempDir $appInfo.FileName
            $copySuccess = Copy-InstallerFromShare -SourcePath $appInfo.FullPath -DestinationPath $localPath
            
            if (-not $copySuccess) {
                Write-Log "Skipping $appName due to copy failure" -Level ERROR
                $failCount++
                continue
            }
            
            # Install application
            $installSuccess = Install-Application -AppName $appName -InstallerPath $localPath -Version $version
            
            if ($installSuccess) {
                # Update version registry
                $installedVersions.$appName = $version
                Write-Log "✓ $appName v$version installed successfully" -Level SUCCESS
                $successCount++
                
                # Clean up installer
                try {
                    Remove-Item -Path $localPath -Force -ErrorAction Stop
                    Write-Log "  Cleaned up installer file" -Level DEBUG
                } catch {
                    Write-Log "  Warning: Could not delete installer: $_" -Level WARNING
                }
            } else {
                Write-Log "✗ $appName v$version installation FAILED" -Level ERROR
                $failCount++
            }
        }
        
        # Save updated version registry
        Save-InstalledVersions -Versions $installedVersions
        
        # Summary
        Write-Log "" -Level INFO
        Write-Log "============================================================" -Level INFO
        Write-Log "UPDATE PROCESS COMPLETE" -Level INFO
        Write-Log "============================================================" -Level INFO
        Write-Log "Successful installations: $successCount" -Level SUCCESS
        Write-Log "Failed installations: $failCount" -Level $(if ($failCount -gt 0) { "ERROR" } else { "INFO" })
        Write-Log "Total runtime: $((Get-Date) - $script:StartTime)" -Level INFO
        
    } catch {
        Write-Log "CRITICAL ERROR in update process: $_" -Level ERROR
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    } finally {
        # Always remove lock file
        Remove-UpdateLock
    }
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

$script:StartTime = Get-Date

# Initialize logging
Initialize-Logging

# Start the update process
Start-VDIUpdateProcess

Write-Log "Script execution completed" -Level INFO
Write-Log "========================================================================================================" -NoConsole

# Exit gracefully
exit 0
