rule findstr_
{
    meta:
        description = "Detection patterns for the tool 'findstr ' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "findstr "
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Find GPP Passwords in SYSVOL - search for occurrences of the term "cpassword" in all XML files within the SYSVOL directory of the domain controller - The "cpassword" string refers to a weakly encrypted password stored in some Group Policy Preferences (GPP) files
        // Reference: N/A
        $string1 = /findstr\s\/S\scpassword\s\$env\:.{0,1000}\\sysvol\\.{0,1000}\.xml/ nocase ascii wide
        // Description: Find GPP Passwords in SYSVOL - search for occurrences of the term "cpassword" in all XML files within the SYSVOL directory of the domain controller - The "cpassword" string refers to a weakly encrypted password stored in some Group Policy Preferences (GPP) files
        // Reference: N/A
        $string2 = /findstr\s\/S\scpassword\s\%.{0,1000}\%\\sysvol\\.{0,1000}\.xml/ nocase ascii wide

    condition:
        any of them
}
