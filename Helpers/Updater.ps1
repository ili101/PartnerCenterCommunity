$PackagesNames = 'Microsoft.IdentityModel.Abstractions', 'Microsoft.Identity.Client', 'Microsoft.Store.PartnerCenter'
$LibPath = '.\lib\'
$Sum = foreach ($PackageName in $PackagesNames) {
    $Package = Install-Package -Name $PackageName -SkipDependencies -Scope CurrentUser -Force -Verbose

    $PackageFrameworks = Get-ChildItem (Join-Path $Package.Payload.Directories[0].Location $Package.Payload.Directories[0].Name lib) -Directory
    foreach ($Framework in ('net6.0', 'netstandard2.0')) {
        if ($PackageFramework = $PackageFrameworks | Where-Object Name -EQ $Framework) {
            break
        }
    }
    if (!$PackageFramework) {
        throw "Could not find a suitable framework for $PackageName"
    }
    $Dlls = Get-ChildItem $PackageFramework -Filter *.dll
    foreach ($Dll in $Dlls) {
        $DllNew = Get-Item $Dll
        $Row = [ordered]@{
            Name = $DllNew.Name
            New  = $DllNew.VersionInfo.FileVersion
        }
        $Existing = if (Test-Path (Join-Path $LibPath $Dll.Name)) {
            $DllExisting = Get-Item (Join-Path $LibPath $Dll.Name)
            $DllExisting.VersionInfo.FileVersion
        }
        $Row.Insert(1, 'Existing', $Existing)
        Copy-Item $Dll $LibPath
        [PSCustomObject]$Row
    }
}
$Sum