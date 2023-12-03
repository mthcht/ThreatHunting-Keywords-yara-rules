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
        $string1 = /.{0,1000}\/dazzleUP\.git.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string2 = /.{0,1000}dazzleUP\.cna.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string3 = /.{0,1000}dazzleUP\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string4 = /.{0,1000}dazzleUP\.sln.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string5 = /.{0,1000}dazzleUP\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string6 = /.{0,1000}dazzleUP\.x32\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string7 = /.{0,1000}dazzleUP\.x64\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string8 = /.{0,1000}dazzleUP_Reflective_DLL.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string9 = /.{0,1000}dazzleUP\-master.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string10 = /.{0,1000}FE8F0D23\-BDD1\-416D\-8285\-F947BA86D155.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string11 = /.{0,1000}hlldz\/dazzleUP.{0,1000}/ nocase ascii wide
        // Description: A tool that detects the privilege escalation vulnerabilities caused by misconfigurations and missing updates in the Windows operating systems.
        // Reference: https://github.com/hlldz/dazzleUP
        $string12 = /.{0,1000}path_dll_hijack\.h.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
