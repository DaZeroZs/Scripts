
$entry = New-Object System.DirectoryServices.DirectoryEntry(
  "LDAP://ldaps.[DOMAIN]:636/c=de",
  "",
  "",
  [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
)

$searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
$searcher.SearchScope = "Subtree"
$searcher.PageSize = 500
$searcher.Filter = "(objectClass=*)"

#$results = $searcher.FindAll()

$searcher.Filter = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=group))"
$searcher.PropertiesToLoad.Clear()
$null = $searcher.PropertiesToLoad.Add("cn")
$null = $searcher.PropertiesToLoad.Add("member")
$null = $searcher.PropertiesToLoad.Add("uniqueMember")
$null = $searcher.PropertiesToLoad.Add("distinguishedName")

$groups = $searcher.FindAll()

$overview = foreach ($g in $groups) {
    $groupName = if ($g.Properties["cn"].Count -gt 0) {
        $g.Properties["cn"][0]
    } else {
        $g.Path
    }

    $members = @()
    if ($g.Properties["member"].Count -gt 0) {
        $members += $g.Properties["member"]
    }
    if ($g.Properties["uniquemember"].Count -gt 0) {
        $members += $g.Properties["uniquemember"]
    }

    foreach ($m in $members) {
        [PSCustomObject]@{
            Group  = $groupName
            Member = [string]$m
        }
    }
}

$overview | Sort-Object Group, Member | Format-Table -AutoSize

$overview |
  Sort-Object Group, Member |
  Export-Csv ".\ldap-group-membership.csv" -NoTypeInformation -Encoding UTF8
