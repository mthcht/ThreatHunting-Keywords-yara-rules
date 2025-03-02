rule Invoke_Pre2kSpray
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Pre2kSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Pre2kSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Enumerate domain machine accounts and perform pre2k password spraying.
        // Reference: https://github.com/eversinc33/Invoke-Pre2kSpray
        $string1 = " Any passwords that were successfully sprayed have been output to" nocase ascii wide
        // Description: Enumerate domain machine accounts and perform pre2k password spraying.
        // Reference: https://github.com/eversinc33/Invoke-Pre2kSpray
        $string2 = /\sPre2kSpray\.ps1/ nocase ascii wide
        // Description: Enumerate domain machine accounts and perform pre2k password spraying.
        // Reference: https://github.com/eversinc33/Invoke-Pre2kSpray
        $string3 = " Starting pre2k spray against " nocase ascii wide
        // Description: Enumerate domain machine accounts and perform pre2k password spraying.
        // Reference: https://github.com/eversinc33/Invoke-Pre2kSpray
        $string4 = /\/Pre2kSpray\.ps1/ nocase ascii wide
        // Description: Enumerate domain machine accounts and perform pre2k password spraying.
        // Reference: https://github.com/eversinc33/Invoke-Pre2kSpray
        $string5 = /\\Pre2kSpray\.ps1/ nocase ascii wide
        // Description: Enumerate domain machine accounts and perform pre2k password spraying.
        // Reference: https://github.com/eversinc33/Invoke-Pre2kSpray
        $string6 = "Invoke-Pre2kSpray" nocase ascii wide
        // Description: Enumerate domain machine accounts and perform pre2k password spraying.
        // Reference: https://github.com/eversinc33/Invoke-Pre2kSpray
        $string7 = "Invoke-SpraySinglePassword" nocase ascii wide

    condition:
        any of them
}
