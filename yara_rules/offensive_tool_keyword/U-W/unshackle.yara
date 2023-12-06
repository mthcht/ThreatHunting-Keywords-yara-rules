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
        $string1 = /\/bin\/unshackle/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string2 = /\/unshackle\.git/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string3 = /\/unshackle\.modules/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string4 = /Fadi002\/unshackle/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string5 = /unshackle\s\-\-/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string6 = /unshackle\-main/ nocase ascii wide
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string7 = /unshackle\-v1\.0\.iso/ nocase ascii wide

    condition:
        any of them
}
