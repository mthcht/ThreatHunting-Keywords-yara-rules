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
        $string1 = /.{0,1000}\-\-dc\-ip\s.{0,1000}\-\-check\-user\-access.{0,1000}/ nocase ascii wide
        // Description: FindUncommonShares.py is a Python equivalent of PowerView's Invoke-ShareFinder.ps1 allowing to quickly find uncommon shares in vast Windows Domains
        // Reference: https://github.com/p0dalirius/FindUncommonShares
        $string2 = /.{0,1000}FindUncommonShares\.git.{0,1000}/ nocase ascii wide
        // Description: FindUncommonShares.py is a Python equivalent of PowerView's Invoke-ShareFinder.ps1 allowing to quickly find uncommon shares in vast Windows Domains
        // Reference: https://github.com/p0dalirius/FindUncommonShares
        $string3 = /.{0,1000}FindUncommonShares\.py\s.{0,1000}/ nocase ascii wide
        // Description: FindUncommonShares.py is a Python equivalent of PowerView's Invoke-ShareFinder.ps1 allowing to quickly find uncommon shares in vast Windows Domains
        // Reference: https://github.com/p0dalirius/FindUncommonShares
        $string4 = /.{0,1000}FindUncommonShares\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
