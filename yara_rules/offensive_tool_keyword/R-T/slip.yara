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
        $string1 = /\s\-\-archive\-type\star\s\-\-mass\-find\s.{0,1000}\s\-\-mass\-find\-mode\ssymlinks\sarchive/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string2 = /\s\-\-archive\-type\szip\s\-\-symlinks\s\"\.\.\/etc\/hosts.{0,1000}linkname\"\sarchive\s\s/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string3 = /\sslip\.py\s/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string4 = /\.\/slip\.py\s/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string5 = /\/path_traversal_dict\.txt/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string6 = /\/slip\.git/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string7 = /\/slip\-main\.zip/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string8 = /\\path_traversal_dict\.txt/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string9 = /\\slip\.py\s/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string10 = /\\slip\-main\.zip/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string11 = /0xless\/slip/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string12 = /python3\sslip\.py/ nocase ascii wide
        // Description: Slip is a CLI tool to create malicious archive files containing path traversal payloads
        // Reference: https://github.com/0xless/slip
        $string13 = /slip.{0,1000}\s\-\-archive\-type\s.{0,1000}\s\-\-compression\s.{0,1000}\s\-\-paths\s.{0,1000}\s\-\-file\-content\s/ nocase ascii wide

    condition:
        any of them
}
