rule slip
{
    meta:
        description = "Detection patterns for the tool 'slip' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "slip"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string1 = /.{0,1000}\s\-\-archive\-type\star\s\-\-mass\-find\s.{0,1000}\s\-\-mass\-find\-mode\ssymlinks\sarchive.{0,1000}/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string2 = /.{0,1000}\s\-\-archive\-type\szip\s\-\-symlinks\s\"\.\.\/etc\/hosts.{0,1000}linkname\"\sarchive\s\s.{0,1000}/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string3 = /.{0,1000}\sslip\.py\s.{0,1000}/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string4 = /.{0,1000}\.\/slip\.py\s.{0,1000}/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string5 = /.{0,1000}\/path_traversal_dict\.txt.{0,1000}/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string6 = /.{0,1000}\/slip\.git/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string7 = /.{0,1000}\/slip\-main\.zip/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string8 = /.{0,1000}\\path_traversal_dict\.txt.{0,1000}/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string9 = /.{0,1000}\\slip\.py\s.{0,1000}/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string10 = /.{0,1000}\\slip\-main\.zip/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string11 = /.{0,1000}0xless\/slip.{0,1000}/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string12 = /.{0,1000}python3\sslip\.py.{0,1000}/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string13 = /.{0,1000}slip.{0,1000}\s\-\-archive\-type\s.{0,1000}\s\-\-compression\s.{0,1000}\s\-\-paths\s.{0,1000}\s\-\-file\-content\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
