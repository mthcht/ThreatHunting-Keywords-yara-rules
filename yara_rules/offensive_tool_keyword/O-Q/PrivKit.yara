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
        $string1 = /\/PrivKit\.git/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string2 = /\/PrivKit\// nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string3 = /\\modifiableautorun\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string4 = /\\PrivKit\\/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string5 = /\\tokenprivileges\.c/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string6 = /\\tokenprivileges\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string7 = /\\unquotedsvcpath\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string8 = /alwaysinstallelevated\.c/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string9 = /alwaysinstallelevated\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string10 = /\-c\scredentialmanager\.c\s\-o\scredentialmanager\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string11 = /\-c\smodifiableautorun\.c\s\-o\smodifiableautorun\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string12 = /\-c\stokenprivileges\.c\s\-o\stokenprivileges\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string13 = /\-c\sunquotedsvcpath\.c\s\-o\sunquotedsvcpath\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string14 = /hijackablepath\.c/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string15 = /hijackablepath\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string16 = /inline\-execute\s.{0,1000}tokenprivileges\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string17 = /Priv\sEsc\sCheck\sBof/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string18 = /privcheck\.cna/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string19 = /privcheck32/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string20 = /PrivKit32/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string21 = /PrivKit\-main/ nocase ascii wide

    condition:
        any of them
}
