<#
.SYNOPSIS
    VDI Patch Manager - Automated Deployment Script
    
.DESCRIPTION
    Automatically deploys and configures the VDI Patch Manager on a Windows Workspace.
    Run this once per Workspace to set up automatic patch management.
    
.PARAMETER PrimaryShare
    UNC path to primary file share (e.g., \\server\patches)
    
.PARAMETER FallbackShare
    UNC path to fallback file share (optional, defaults to same as primary)
    
.PARAMETER ScriptSource
    Path to VDI-Patch-Manager.ps1 (local file or UNC path)
    
.PARAMETER TestOnly
    Test configuration without creating scheduled task
    
.EXAMPLE
    .\Deploy-VDI-PatchManager.ps1 -PrimaryShare "\\fs01.company.com\patches"
    
.EXAMPLE
    .\Deploy-VDI-PatchManager.ps1 -PrimaryShare "\\prod-fs\patches" -FallbackShare "\\nonprod-fs\patches" -ScriptSource "\\deploy\scripts\VDI-Patch-Manager.ps1"
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="UNC path to primary file share")]
    [ValidatePattern('^\\\\[^\\]+\\[^\\]+')]
    [string]$PrimaryShare,
    
    [Parameter(Mandatory=$false, HelpMessage="UNC path to fallback file share")]
    [string]$FallbackShare = "",
    
    [Parameter(Mandatory=$false, HelpMessage="Path to VDI-Patch-Manager.ps1")]
    [string]$ScriptSource = ".\VDI-Patch-Manager.ps1",
    
    [Parameter(Mandatory=$false)]
    [switch]$TestOnly
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$DeployConfig = @{
    ScriptDir = "C:\Scripts"
    ScriptName = "VDI-Patch-Manager.ps1"
    TaskName = "VDI Patch Manager"
    LogFile = "C:\temp\VDIupdates\deployment.log"
}

if ([string]::IsNullOrEmpty($FallbackShare)) {
    $FallbackShare = $PrimaryShare
}

# ============================================================================
# LOGGING
# ============================================================================

function Write-DeployLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Ensure log directory exists
    $logDir = Split-Path $DeployConfig.LogFile
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    # Write to file
    Add-Content -Path $DeployConfig.LogFile -Value $logMessage
    
    # Write to console with color
    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red' }
        default   { 'White' }
    }
    Write-Host $logMessage -ForegroundColor $color
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

function Test-Prerequisites {
    Write-DeployLog "Validating prerequisites..." -Level INFO
    
    $errors = @()
    
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $errors += "Script must run as Administrator"
    } else {
        Write-DeployLog "  ✓ Running as Administrator" -Level SUCCESS
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $errors += "PowerShell 5.1+ required (current: $($PSVersionTable.PSVersion))"
    } else {
        Write-DeployLog "  ✓ PowerShell version: $($PSVersionTable.PSVersion)" -Level SUCCESS
    }
    
    # Check if source script exists
    if (-not (Test-Path $ScriptSource)) {
        $errors += "Source script not found: $ScriptSource"
    } else {
        Write-DeployLog "  ✓ Source script found: $ScriptSource" -Level SUCCESS
    }
    
    # Test file share connectivity
    Write-DeployLog "  Testing file share connectivity..." -Level INFO
    if (Test-Path $PrimaryShare -ErrorAction SilentlyContinue) {
        Write-DeployLog "    ✓ Primary share accessible: $PrimaryShare" -Level SUCCESS
    } else {
        Write-DeployLog "    ✗ Primary share NOT accessible: $PrimaryShare" -Level WARNING
        $errors += "Cannot access primary share: $PrimaryShare"
    }
    
    if ($FallbackShare -ne $PrimaryShare) {
        if (Test-Path $FallbackShare -ErrorAction SilentlyContinue) {
            Write-DeployLog "    ✓ Fallback share accessible: $FallbackShare" -Level SUCCESS
        } else {
            Write-DeployLog "    ✗ Fallback share NOT accessible: $FallbackShare" -Level WARNING
        }
    }
    
    if ($errors.Count -gt 0) {
        Write-DeployLog "Prerequisites check FAILED:" -Level ERROR
        foreach ($err in $errors) {
            Write-DeployLog "  - $err" -Level ERROR
        }
        return $false
    }
    
    Write-DeployLog "Prerequisites check PASSED" -Level SUCCESS
    return $true
}

# ============================================================================
# DEPLOYMENT FUNCTIONS
# ============================================================================

function Install-Script {
    Write-DeployLog "Installing VDI Patch Manager script..." -Level INFO
    
    try {
        # Create script directory
        if (-not (Test-Path $DeployConfig.ScriptDir)) {
            New-Item -Path $DeployConfig.ScriptDir -ItemType Directory -Force | Out-Null
            Write-DeployLog "  Created directory: $($DeployConfig.ScriptDir)" -Level SUCCESS
        }
        
        $destPath = Join-Path $DeployConfig.ScriptDir $DeployConfig.ScriptName
        
        # Read source script
        $scriptContent = Get-Content $ScriptSource -Raw
        
        # Update file share paths in script
        $scriptContent = $scriptContent -replace '(PrimaryShare\s*=\s*")[^"]*(")', "`$1$PrimaryShare`$2"
        $scriptContent = $scriptContent -replace '(FallbackShare\s*=\s*")[^"]*(")', "`$1$FallbackShare`$2"
        
        # Write modified script
        Set-Content -Path $destPath -Value $scriptContent -Force
        
        Write-DeployLog "  ✓ Script deployed to: $destPath" -Level SUCCESS
        Write-DeployLog "  ✓ Configured primary share: $PrimaryShare" -Level SUCCESS
        Write-DeployLog "  ✓ Configured fallback share: $FallbackShare" -Level SUCCESS
        
        return $destPath
        
    } catch {
        Write-DeployLog "  ✗ Failed to install script: $_" -Level ERROR
        throw
    }
}

function Set-ExecutionPolicyIfNeeded {
    Write-DeployLog "Checking PowerShell execution policy..." -Level INFO
    
    $currentPolicy = Get-ExecutionPolicy -Scope LocalMachine
    
    if ($currentPolicy -eq 'Restricted' -or $currentPolicy -eq 'Undefined') {
        try {
            Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
            Write-DeployLog "  ✓ Execution policy set to RemoteSigned" -Level SUCCESS
        } catch {
            Write-DeployLog "  ✗ Failed to set execution policy: $_" -Level ERROR
            throw
        }
    } else {
        Write-DeployLog "  ✓ Execution policy is: $currentPolicy (OK)" -Level SUCCESS
    }
}

function Register-StartupTask {
    param([string]$ScriptPath)
    
    Write-DeployLog "Registering scheduled task for startup execution..." -Level INFO
    
    try {
        # Check if task already exists
        $existingTask = Get-ScheduledTask -TaskName $DeployConfig.TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Write-DeployLog "  Task already exists, removing old version..." -Level WARNING
            Unregister-ScheduledTask -TaskName $DeployConfig.TaskName -Confirm:$false
        }
        
        # Create action
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
        
        # Create trigger (at startup, 2-minute delay)
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $trigger.Delay = "PT2M"
        
        # Create principal (run as SYSTEM)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Create settings
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 10) `
            -ExecutionTimeLimit (New-TimeSpan -Hours 1)
        
        # Register task
        Register-ScheduledTask `
            -TaskName $DeployConfig.TaskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description "Automatic software updates from network file share for AWS Workspaces VDI" | Out-Null
        
        Write-DeployLog "  ✓ Scheduled task created successfully" -Level SUCCESS
        Write-DeployLog "  ✓ Task will run at startup with 2-minute delay" -Level SUCCESS
        
    } catch {
        Write-DeployLog "  ✗ Failed to register scheduled task: $_" -Level ERROR
        throw
    }
}

function Test-Deployment {
    param([string]$ScriptPath)
    
    Write-DeployLog "Testing deployment..." -Level INFO
    
    try {
        # Test 1: Script file exists
        if (Test-Path $ScriptPath) {
            Write-DeployLog "  ✓ Script file exists" -Level SUCCESS
        } else {
            Write-DeployLog "  ✗ Script file not found" -Level ERROR
            return $false
        }
        
        # Test 2: Scheduled task exists
        $task = Get-ScheduledTask -TaskName $DeployConfig.TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Write-DeployLog "  ✓ Scheduled task exists" -Level SUCCESS
            $taskInfo = Get-ScheduledTaskInfo -TaskName $DeployConfig.TaskName
            Write-DeployLog "    Task state: $($task.State)" -Level INFO
        } else {
            Write-DeployLog "  ✗ Scheduled task not found" -Level ERROR
            return $false
        }
        
        # Test 3: Execution policy
        $policy = Get-ExecutionPolicy -Scope LocalMachine
        if ($policy -ne 'Restricted') {
            Write-DeployLog "  ✓ Execution policy allows script execution ($policy)" -Level SUCCESS
        } else {
            Write-DeployLog "  ✗ Execution policy too restrictive ($policy)" -Level ERROR
            return $false
        }
        
        # Test 4: Manual execution test
        Write-DeployLog "  Running manual test execution..." -Level INFO
        Write-DeployLog "    (This may take 1-2 minutes...)" -Level INFO
        
        $testResult = schtasks /run /tn "$($DeployConfig.TaskName)" 2>&1
        Start-Sleep -Seconds 5
        
        # Check if log file was created
        if (Test-Path "C:\temp\VDIupdates\log.txt") {
            Write-DeployLog "  ✓ Manual test execution successful (log file created)" -Level SUCCESS
            
            # Show last few lines of log
            $logLines = Get-Content "C:\temp\VDIupdates\log.txt" -Tail 10
            Write-DeployLog "    Last 10 log lines:" -Level INFO
            foreach ($line in $logLines) {
                Write-DeployLog "      $line" -Level INFO
            }
            
        } else {
            Write-DeployLog "  ⚠ Manual test may not have completed (log file not found yet)" -Level WARNING
        }
        
        return $true
        
    } catch {
        Write-DeployLog "  ✗ Deployment test failed: $_" -Level ERROR
        return $false
    }
}

# ============================================================================
# MAIN DEPLOYMENT WORKFLOW
# ============================================================================

function Start-Deployment {
    Write-DeployLog "========================================================================================================" -Level INFO
    Write-DeployLog "VDI PATCH MANAGER - DEPLOYMENT SCRIPT" -Level INFO
    Write-DeployLog "========================================================================================================" -Level INFO
    Write-DeployLog "Computer: $env:COMPUTERNAME" -Level INFO
    Write-DeployLog "User: $env:USERNAME" -Level INFO
    Write-DeployLog "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO
    Write-DeployLog "Primary Share: $PrimaryShare" -Level INFO
    Write-DeployLog "Fallback Share: $FallbackShare" -Level INFO
    Write-DeployLog "Test Only Mode: $TestOnly" -Level INFO
    Write-DeployLog "========================================================================================================" -Level INFO
    Write-DeployLog "" -Level INFO
    
    # Step 1: Prerequisites
    if (-not (Test-Prerequisites)) {
        Write-DeployLog "Deployment ABORTED due to prerequisite failures" -Level ERROR
        return $false
    }
    Write-DeployLog "" -Level INFO
    
    # Step 2: Set execution policy
    Set-ExecutionPolicyIfNeeded
    Write-DeployLog "" -Level INFO
    
    # Step 3: Install script
    $scriptPath = Install-Script
    Write-DeployLog "" -Level INFO
    
    # Step 4: Register scheduled task (unless test-only mode)
    if (-not $TestOnly) {
        Register-StartupTask -ScriptPath $scriptPath
        Write-DeployLog "" -Level INFO
        
        # Step 5: Test deployment
        $testSuccess = Test-Deployment -ScriptPath $scriptPath
        Write-DeployLog "" -Level INFO
        
        if ($testSuccess) {
            Write-DeployLog "========================================================================================================" -Level INFO
            Write-DeployLog "✓ DEPLOYMENT SUCCESSFUL!" -Level SUCCESS
            Write-DeployLog "========================================================================================================" -Level INFO
            Write-DeployLog "Next steps:" -Level INFO
            Write-DeployLog "  1. Review the log: C:\temp\VDIupdates\log.txt" -Level INFO
            Write-DeployLog "  2. Reboot the Workspace to test automatic startup execution" -Level INFO
            Write-DeployLog "  3. Check version registry: C:\temp\VDIupdates\versions.json" -Level INFO
            Write-DeployLog "========================================================================================================" -Level INFO
            return $true
        } else {
            Write-DeployLog "⚠ Deployment completed with warnings - manual verification recommended" -Level WARNING
            return $false
        }
    } else {
        Write-DeployLog "========================================================================================================" -Level INFO
        Write-DeployLog "✓ TEST MODE - Configuration validated successfully" -Level SUCCESS
        Write-DeployLog "========================================================================================================" -Level INFO
        Write-DeployLog "To complete deployment, run without -TestOnly parameter" -Level INFO
        Write-DeployLog "========================================================================================================" -Level INFO
        return $true
    }
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

try {
    $success = Start-Deployment
    
    if ($success) {
        exit 0
    } else {
        Write-DeployLog "Deployment completed with errors" -Level ERROR
        exit 1
    }
    
} catch {
    Write-DeployLog "CRITICAL ERROR during deployment: $_" -Level ERROR
    Write-DeployLog "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    exit 1
}
