rule Invoke_ShareHunter
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ShareHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ShareHunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Enumerate the Domain for Readable and Writable Shares
        // Reference: https://github.com/Leo4j/Invoke-ShareHunter
        $string1 = /\\Shares_CleanupCommand\.txt/ nocase ascii wide
        // Description: Enumerate the Domain for Readable and Writable Shares
        // Reference: https://github.com/Leo4j/Invoke-ShareHunter
        $string2 = /\\Shares_Readable\.txt/ nocase ascii wide
        // Description: Enumerate the Domain for Readable and Writable Shares
        // Reference: https://github.com/Leo4j/Invoke-ShareHunter
        $string3 = /\\Shares_Writable\.txt\\"/ nocase ascii wide
        // Description: Enumerate the Domain for Readable and Writable Shares
        // Reference: https://github.com/Leo4j/Invoke-ShareHunter
        $string4 = "Invoke-ShareHunter " nocase ascii wide
        // Description: Enumerate the Domain for Readable and Writable Shares
        // Reference: https://github.com/Leo4j/Invoke-ShareHunter
        $string5 = /Invoke\-ShareHunter\.ps1/ nocase ascii wide
        // Description: Enumerate the Domain for Readable and Writable Shares
        // Reference: https://github.com/Leo4j/Invoke-ShareHunter
        $string6 = /Invoke\-URLFileClean\s\-WritableShares\s.{0,1000}\s\-URLAttackFileName/ nocase ascii wide

    condition:
        any of them
}
