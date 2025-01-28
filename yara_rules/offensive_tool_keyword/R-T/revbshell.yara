rule revbshell
{
    meta:
        description = "Detection patterns for the tool 'revbshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "revbshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string1 = /\/revbshell\.git/ nocase ascii wide
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string2 = /\\revbshell\-master/ nocase ascii wide
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string3 = "5f01ca453b976669370a3d5975837773107dd5522e8259dccda788993bb0da89" nocase ascii wide
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string4 = "bitsadmin/revbshell" nocase ascii wide
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string5 = "dcd8b443ee740b4ccd6674dd1e6b6cfccd9a202c282a67e06ce2f4aaa8a66d95" nocase ascii wide
        // Description: ReVBShell - Reverse VBS Shell
        // Reference: https://github.com/bitsadmin/revbshell
        $string6 = /pentest\-script\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
