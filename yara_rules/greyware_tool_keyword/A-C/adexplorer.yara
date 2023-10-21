rule adexplorer
{
    meta:
        description = "Detection patterns for the tool 'adexplorer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adexplorer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Active Directory Explorer (AD Explorer) is an advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database. It can be abused by malicious actors
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
        $string1 = /adexplorer\.exe/ nocase ascii wide
        // Description: Active Directory Explorer (AD Explorer) is an advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database. It can be abused by malicious actors
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
        $string2 = /adexplorer\.zip/ nocase ascii wide
        // Description: Active Directory Explorer (AD Explorer) is an advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database. It can be abused by malicious actors
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
        $string3 = /adexplorer64\.exe/ nocase ascii wide
        // Description: Active Directory Explorer (AD Explorer) is an advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database. It can be abused by malicious actors
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
        $string4 = /adexplorer64a\.exe/ nocase ascii wide

    condition:
        any of them
}