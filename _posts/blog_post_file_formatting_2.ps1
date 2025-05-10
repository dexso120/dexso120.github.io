# Script for blog post formatting

# First remove all spaces in png filenames
<#
$Files = Get-ChildItem -Path ".\Screenshots" -File

ForEach ($File in $Files){
    Write-Host "Processing File: $($File.Name)"
    $NewFileName = $File.Name.Replace(' ', '_')
    Rename-Item -Path ".\Screenshots\$($File.Name)" -NewName "$($NewFileName)"
}
#>

# Then replace the filenames in the markdown file

$MarkDownFileName = Read-Host "Enter full markdown filename (e.g. Writeup.md):"

$ImageFolder = Read-Host "Enter screenshot folder name (under /assets/img/):"

$MarkDownFilePath = ".\$MarkDownFileName"

$MarkDownContent = Get-Content -Path $MarkDownFilePath

$regex = ".*\.png\]\]"

ForEach ($line in $MarkDownContent){
    if ($line -match $regex){
        Write-Host "Line match: $($line)"
        $filename = $line.split("/")[-1].split("[[")[-1].split("]]")[0]
        $newline = "![Screenshot](/assets/img/$ImageFolder/$filename)"
        #Write-Host $newline
        $new_content = $(Get-Content -Path $MarkDownFilePath).replace($line, $newline)
        $new_content | Set-Content -Path $MarkDownFilePath
    }
}