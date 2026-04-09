Get-ChildItem -Recurse -Include *.js | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    $content = $content -replace ' ? .', '?.'
    Set-Content $_.FullName $content
}