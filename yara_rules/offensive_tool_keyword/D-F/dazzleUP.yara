rule dazzleUP
{
    meta:
        description = "Detection patterns for the tool 'dazzleUP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dazzleUP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string1 = /\/dazzleUP\.git/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string2 = /dazzleUP\.cna/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string3 = /dazzleUP\.exe/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string4 = /dazzleUP\.sln/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string5 = /dazzleUP\.vcxproj/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string6 = /dazzleUP\.x32\.exe/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string7 = /dazzleUP\.x64\.exe/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string8 = /dazzleUP_Reflective_DLL/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string9 = /dazzleUP\-master/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string10 = /FE8F0D23\-BDD1\-416D\-8285\-F947BA86D155/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string11 = /hlldz\/dazzleUP/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string12 = /path_dll_hijack\.h/ nocase ascii wide

    condition:
        any of them
}
