rule pysnaffler
{
    meta:
        description = "Detection patterns for the tool 'pysnaffler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysnaffler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string1 = /\ssnaffler\.py\s/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string2 = /\.\/snaffler_downloads/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string3 = /\/pysnaffler\.git/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string4 = /\/snaffler\.py/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string5 = /\\pysnaffler\\pysnaffler\\/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string6 = /\\snaffler\.py/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string7 = /from\spysnaffler\.rules\.constants\simport\s/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string8 = /from\spysnaffler\.rules\.rule\simport\sSnaffleRule/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string9 = /from\spysnaffler\.ruleset\simport\sSnafflerRuleSet/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string10 = /from\spysnaffler\.scanner\simport\sSnafflerScanner/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string11 = /from\spysnaffler\.snaffler\simport\s/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string12 = /pysnaffler\s\-/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string13 = /pysnaffler\s\'smb2\+kerberos\+password\:/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string14 = /pysnaffler\s\'smb2\+ntlm\-nt\:\/\// nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string15 = /pysnaffler\s\'smb2\+ntlm\-password\:\/\// nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string16 = /pysnaffler\.whatif\:main/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string17 = /pysnaffler\/_version\.py/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string18 = /pysnaffler\-main/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string19 = /skelsec\/pysnaffler/ nocase ascii wide

    condition:
        any of them
}
