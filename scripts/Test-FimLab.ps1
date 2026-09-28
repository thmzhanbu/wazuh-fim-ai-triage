# Proposed repeatable lab test helper, not a transcript of the original commands.
# Run ONE stage at a time in the Windows lab VM and verify its alert before the next.
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Create', 'Modify', 'Delete')]
    [string]$Stage
)

$ErrorActionPreference = 'Stop'
$LabDirectory = 'C:\FIM-Lab'
$LabFile = 'C:\FIM-Lab\critical-config.txt'

function Assert-NotReparsePoint([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $Item = Get-Item -LiteralPath $Path -Force
        if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Refusing a symbolic link or junction: $Path"
        }
    }
}

Assert-NotReparsePoint $LabDirectory
Assert-NotReparsePoint $LabFile

switch ($Stage) {
    'Create' {
        if (Test-Path -LiteralPath $LabFile) {
            throw 'Lab file already exists. Create will not overwrite it.'
        }
        if ($PSCmdlet.ShouldProcess($LabFile, 'Create the lab test file; expected rule 100100')) {
            if (-not (Test-Path -LiteralPath $LabDirectory)) {
                New-Item -Path $LabDirectory -ItemType Directory | Out-Null
            }
            # No -Force: an existing file must not be replaced.
            New-Item -Path $LabFile -ItemType File -Value "status=baseline-lab`r`n" | Out-Null
            Get-FileHash -LiteralPath $LabFile -Algorithm SHA256
        }
    }
    'Modify' {
        if (-not (Test-Path -LiteralPath $LabFile -PathType Leaf)) {
            throw 'Lab file is missing. Run and verify Create first.'
        }
        if ($PSCmdlet.ShouldProcess($LabFile, 'Append a lab marker; expected rule 100101')) {
            Add-Content -LiteralPath $LabFile -Value 'status=modified-by-lab' -Encoding Ascii
            Get-FileHash -LiteralPath $LabFile -Algorithm SHA256
        }
    }
    'Delete' {
        if (-not (Test-Path -LiteralPath $LabFile -PathType Leaf)) {
            throw 'Lab file is missing. There is nothing to delete.'
        }
        if ($PSCmdlet.ShouldProcess($LabFile, 'Delete only the lab test file; expected rule 100102')) {
            Remove-Item -LiteralPath $LabFile
            Write-Output 'Lab test file deleted. Verify custom rule 100102.'
        }
    }
}
