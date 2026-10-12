param(
    [string]$Python = "python",
    [string]$Core = "",
    [switch]$Direct,
    [ValidateRange(0, 3600)]
    [int]$RetryDelaySeconds = 60
)

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
$logDirectory = Join-Path $projectRoot "data"
$logPath = Join-Path $logDirectory "local-refresh.log"
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
if ((Test-Path -LiteralPath $logPath) -and (Get-Item -LiteralPath $logPath).Length -gt 5MB) {
    Move-Item -LiteralPath $logPath -Destination ($logPath + ".previous") -Force
}
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$verifyArguments = @("-u", (Join-Path $projectRoot "verify.py"))
if ($Core) { $verifyArguments += @("--core", $Core) }
if ($Direct) { $verifyArguments += "--proxy=" }
$resultCode = 1
Push-Location -LiteralPath $projectRoot
try {
    "[$(Get-Date -Format o)] Starting local verification" | Out-File -LiteralPath $logPath -Encoding utf8 -Append
    $pythonCommand = Get-Command -Name $Python -CommandType Application -ErrorAction Stop
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        "[$(Get-Date -Format o)] Attempt $attempt/3" | Out-File -LiteralPath $logPath -Encoding utf8 -Append
        # Python logging writes to stderr; native stderr must be logged rather than
        # converted into a terminating PowerShell error on Windows PowerShell 5.1.
        $ErrorActionPreference = "Continue"
        try {
            $LASTEXITCODE = $null
            & $pythonCommand.Source @verifyArguments 2>&1 |
                ForEach-Object { $_.ToString() } |
                Out-File -LiteralPath $logPath -Encoding utf8 -Append -ErrorAction Stop
            if ($null -eq $LASTEXITCODE) { throw "Python did not return an exit code" }
            $resultCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = "Stop"
        }
        "[$(Get-Date -Format o)] Attempt $attempt exit code: $resultCode" |
            Out-File -LiteralPath $logPath -Encoding utf8 -Append
        if (($resultCode -notin @(1, 3)) -or ($attempt -eq 3)) { break }
        "[$(Get-Date -Format o)] Retrying in $RetryDelaySeconds seconds using completed verification checkpoints" |
            Out-File -LiteralPath $logPath -Encoding utf8 -Append
        if ($RetryDelaySeconds -gt 0) { Start-Sleep -Seconds $RetryDelaySeconds }
    }
} catch {
    $resultCode = 1
    "[$(Get-Date -Format o)] Runner failed: $($_.Exception.Message)" |
        Out-File -LiteralPath $logPath -Encoding utf8 -Append
} finally {
    "[$(Get-Date -Format o)] Exit code: $resultCode" | Out-File -LiteralPath $logPath -Encoding utf8 -Append
    Pop-Location
}
exit $resultCode
