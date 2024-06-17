rule pcunlocker
{
    meta:
        description = "Detection patterns for the tool 'pcunlocker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pcunlocker"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Reset and unlock forgotten Windows login password
        // Reference: https://www.pcunlocker.com/
        $string1 = /\/download\/pcunlocker/ nocase ascii wide
        // Description: Reset and unlock forgotten Windows login password
        // Reference: https://www.pcunlocker.com/
        $string2 = /\/pcunlocker\.iso/ nocase ascii wide
        // Description: Reset and unlock forgotten Windows login password
        // Reference: https://www.pcunlocker.com/
        $string3 = /\/pcunlocker_trial\.zip/ nocase ascii wide
        // Description: Reset and unlock forgotten Windows login password
        // Reference: https://www.pcunlocker.com/
        $string4 = /\\pcunlocker\.iso/ nocase ascii wide
        // Description: Reset and unlock forgotten Windows login password
        // Reference: https://www.pcunlocker.com/
        $string5 = /\\pcunlocker_trial\.zip/ nocase ascii wide
        // Description: Reset and unlock forgotten Windows login password
        // Reference: https://www.pcunlocker.com/
        $string6 = /pcunlocker_ent_trial\.zip/ nocase ascii wide

    condition:
        any of them
}
