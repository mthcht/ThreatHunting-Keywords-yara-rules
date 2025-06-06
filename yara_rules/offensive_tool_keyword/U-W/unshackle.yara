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
        $string1 = "/bin/unshackle"
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string2 = /\/unshackle\.git/
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string3 = /\/unshackle\.modules/
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string4 = "Fadi002/unshackle"
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string5 = "unshackle --"
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string6 = "unshackle-main"
        // Description: Unshackle is an open-source tool to bypass Windows and Linux user passwords from a bootable USB based on Linux
        // Reference: https://github.com/Fadi002/unshackle
        $string7 = /unshackle\-v1\.0\.iso/

    condition:
        any of them
}
