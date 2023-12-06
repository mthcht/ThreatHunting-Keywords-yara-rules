rule FindUncommonShares
{
    meta:
        description = "Detection patterns for the tool 'FindUncommonShares' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FindUncommonShares"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: FindUncommonShares.py is a Python equivalent of PowerView's Invoke-ShareFinder.ps1 allowing to quickly find uncommon shares in vast Windows Domains
        // Reference: https://github.com/p0dalirius/FindUncommonShares
        $string1 = /\-\-dc\-ip\s.{0,1000}\-\-check\-user\-access/ nocase ascii wide
        // Description: FindUncommonShares.py is a Python equivalent of PowerView's Invoke-ShareFinder.ps1 allowing to quickly find uncommon shares in vast Windows Domains
        // Reference: https://github.com/p0dalirius/FindUncommonShares
        $string2 = /FindUncommonShares\.git/ nocase ascii wide
        // Description: FindUncommonShares.py is a Python equivalent of PowerView's Invoke-ShareFinder.ps1 allowing to quickly find uncommon shares in vast Windows Domains
        // Reference: https://github.com/p0dalirius/FindUncommonShares
        $string3 = /FindUncommonShares\.py\s/ nocase ascii wide
        // Description: FindUncommonShares.py is a Python equivalent of PowerView's Invoke-ShareFinder.ps1 allowing to quickly find uncommon shares in vast Windows Domains
        // Reference: https://github.com/p0dalirius/FindUncommonShares
        $string4 = /FindUncommonShares\-main/ nocase ascii wide

    condition:
        any of them
}
