rule impersonate
{
    meta:
        description = "Detection patterns for the tool 'impersonate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impersonate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string1 = /\sImpersonate\.exe\s/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string2 = /\simpersonate\.py\s/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string3 = /\/Impersonate\.exe/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string4 = /\/impersonate\.git/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string5 = /\/impersonate\.py/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string6 = /\\Impersonate\.exe/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string7 = /\\impersonate\.py/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string8 = /\\Impersonate\\Impersonate\.cpp/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string9 = /\\Temp\\Impersonate\.exe/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string10 = /00630066\-0B43\-474E\-A93B\-417CF1A65195/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string11 = /Impersonate\.exe\sadduser\s/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string12 = /Impersonate\.exe\sexec\s/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string13 = /Impersonate\.exe\slist\s/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string14 = /Impersonate\.exe\slist/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string15 = /impersonate\-main\.zip/ nocase ascii wide
        // Description: A windows token impersonation tool
        // Reference: https://github.com/sensepost/impersonate
        $string16 = /sensepost\/impersonate/ nocase ascii wide

    condition:
        any of them
}
