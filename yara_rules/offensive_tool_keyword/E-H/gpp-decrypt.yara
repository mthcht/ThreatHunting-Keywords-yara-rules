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
        $string1 = /.{0,1000}\/gpp\-decrypt.{0,1000}/ nocase ascii wide
        // Description: Decrypt the given Group Policy Preferences
        // Reference: https://gitlab.com/kalilinux/packages/gpp-decrypt
        $string2 = /.{0,1000}apt\sinstall\sgpp\-decrypt.{0,1000}/ nocase ascii wide
        // Description: Decrypt the given Group Policy Preferences
        // Reference: https://gitlab.com/kalilinux/packages/gpp-decrypt
        $string3 = /.{0,1000}gpp\-decrypt\s.{0,1000}/ nocase ascii wide
        // Description: Decrypt the given Group Policy Preferences
        // Reference: https://gitlab.com/kalilinux/packages/gpp-decrypt
        $string4 = /.{0,1000}gpp\-decrypt\.rb.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
