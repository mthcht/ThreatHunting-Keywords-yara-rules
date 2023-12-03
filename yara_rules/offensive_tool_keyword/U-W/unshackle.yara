rule unshackle
{
    meta:
        description = "Detection patterns for the tool 'unshackle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unshackle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string1 = /.{0,1000}\/bin\/unshackle.{0,1000}/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string2 = /.{0,1000}\/unshackle\.git.{0,1000}/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string3 = /.{0,1000}\/unshackle\.modules.{0,1000}/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string4 = /.{0,1000}Fadi002\/unshackle.{0,1000}/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string5 = /.{0,1000}unshackle\s\-\-.{0,1000}/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string6 = /.{0,1000}unshackle\-main.{0,1000}/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string7 = /.{0,1000}unshackle\-v1\.0\.iso.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
