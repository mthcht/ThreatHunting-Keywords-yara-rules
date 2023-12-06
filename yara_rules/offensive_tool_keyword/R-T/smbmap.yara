rule smbmap
{
    meta:
        description = "Detection patterns for the tool 'smbmap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smbmap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string1 = /\s\-H\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-r\s.{0,1000}C\$\/Users/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string2 = /\s\-\-host\-file\s.{0,1000}\.txt\s\-u\s.{0,1000}\s\-\-prompt\s\-\-admin\s\-\-no\-banner/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string3 = /\/smbmap\.git/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string4 = /\\\\\\\\.{0,1000}\\\\.{0,1000}\\\\Get\-FileLockProcess\.ps1/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string5 = /cmd\s\/c\s.{0,1000}if\sexist\s.{0,1000}\.txt\secho\sImHere/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string6 = /install\ssmbmap/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string7 = /install\ssmbmap/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string8 = /ShawnDEvans\/smbmap/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string9 = /smbmap\s\-/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string10 = /smbmap\.py\s/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string11 = /smbmap\.smbmap/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string12 = /smbmap\-master/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string13 = /\-x\s.{0,1000}net\sgroup\s.{0,1000}Domain\sAdmins.{0,1000}\s\/domain/ nocase ascii wide

    condition:
        any of them
}
