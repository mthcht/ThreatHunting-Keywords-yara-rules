rule PrivKit
{
    meta:
        description = "Detection patterns for the tool 'PrivKit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivKit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string1 = /.{0,1000}\/PrivKit\.git.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string2 = /.{0,1000}\/PrivKit\/.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string3 = /.{0,1000}\\modifiableautorun\.o.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string4 = /.{0,1000}\\PrivKit\\.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string5 = /.{0,1000}\\tokenprivileges\.c.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string6 = /.{0,1000}\\tokenprivileges\.o.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string7 = /.{0,1000}\\unquotedsvcpath\.o.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string8 = /.{0,1000}alwaysinstallelevated\.c.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string9 = /.{0,1000}alwaysinstallelevated\.o.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string10 = /.{0,1000}\-c\scredentialmanager\.c\s\-o\scredentialmanager\.o.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string11 = /.{0,1000}\-c\smodifiableautorun\.c\s\-o\smodifiableautorun\.o.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string12 = /.{0,1000}\-c\stokenprivileges\.c\s\-o\stokenprivileges\.o.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string13 = /.{0,1000}\-c\sunquotedsvcpath\.c\s\-o\sunquotedsvcpath\.o.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string14 = /.{0,1000}hijackablepath\.c.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string15 = /.{0,1000}hijackablepath\.o.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string16 = /.{0,1000}inline\-execute\s.{0,1000}tokenprivileges\.o.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string17 = /.{0,1000}Priv\sEsc\sCheck\sBof.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string18 = /.{0,1000}privcheck\.cna.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string19 = /.{0,1000}privcheck32.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string20 = /.{0,1000}PrivKit32.{0,1000}/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string21 = /.{0,1000}PrivKit\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
