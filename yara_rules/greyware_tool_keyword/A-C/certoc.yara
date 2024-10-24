rule certoc
{
    meta:
        description = "Detection patterns for the tool 'certoc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "certoc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: download from github with certoc
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Certoc/
        $string1 = /certoc\.exe\s\-GetCACAPS\shttps\:\/\/raw\.githubusercontent\.com/ nocase ascii wide

    condition:
        any of them
}
