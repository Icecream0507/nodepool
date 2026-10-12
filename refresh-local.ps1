param(
    [string]$Python = "python",
    [string]$Core = "",
    [switch]$Direct
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
    # Python logging writes to stderr; native stderr must be logged rather than
    # converted into a terminating PowerShell error on Windows PowerShell 5.1.
    $ErrorActionPreference = "Continue"
    try {
        & $pythonCommand.Source @verifyArguments 2>&1 |
            ForEach-Object { $_.ToString() } |
            Out-File -LiteralPath $logPath -Encoding utf8 -Append -ErrorAction Stop
        $resultCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = "Stop"
    }
} catch {
    "[$(Get-Date -Format o)] Runner failed: $($_.Exception.Message)" |
        Out-File -LiteralPath $logPath -Encoding utf8 -Append
} finally {
    "[$(Get-Date -Format o)] Exit code: $resultCode" | Out-File -LiteralPath $logPath -Encoding utf8 -Append
    Pop-Location
}
exit $resultCode
