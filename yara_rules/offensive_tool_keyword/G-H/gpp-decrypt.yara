rule gpp_decrypt
{
    meta:
        description = "Detection patterns for the tool 'gpp-decrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gpp-decrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Decrypt the given Group Policy Preferences
        // Reference: https://gitlab.com/kalilinux/packages/gpp-decrypt
        $string1 = /\/gpp\-decrypt/ nocase ascii wide
        // Description: Decrypt the given Group Policy Preferences
        // Reference: https://gitlab.com/kalilinux/packages/gpp-decrypt
        $string2 = /apt\sinstall\sgpp\-decrypt/ nocase ascii wide
        // Description: Decrypt the given Group Policy Preferences
        // Reference: https://gitlab.com/kalilinux/packages/gpp-decrypt
        $string3 = /gpp\-decrypt\s/ nocase ascii wide
        // Description: Decrypt the given Group Policy Preferences
        // Reference: https://gitlab.com/kalilinux/packages/gpp-decrypt
        $string4 = /gpp\-decrypt\.rb/ nocase ascii wide

    condition:
        any of them
}
