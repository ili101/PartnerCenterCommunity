$CmdLet = Read-Host 'CmdLet name'

$Auto = 'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'WhatIf', 'Confirm'
$Rows = ((Get-Command  $CmdLet).Parameters.Keys | Where-Object { $_ -notin $Auto } | Join-String -FormatString "| {0} |    |" -Separator "`n")
Set-Clipboard ("### $CmdLet", '| Param | Status |', '| -- | -- |', $Rows -join "`n")