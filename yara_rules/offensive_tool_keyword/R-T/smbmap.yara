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
        $string1 = /.{0,1000}\s\-H\s.{0,1000}\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-r\s.{0,1000}C\$\/Users.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string2 = /.{0,1000}\s\-\-host\-file\s.{0,1000}\.txt\s\-u\s.{0,1000}\s\-\-prompt\s\-\-admin\s\-\-no\-banner.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string3 = /.{0,1000}\/smbmap\.git.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string4 = /.{0,1000}\\\\\\\\.{0,1000}\\\\.{0,1000}\\\\Get\-FileLockProcess\.ps1.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string5 = /.{0,1000}cmd\s\/c\s.{0,1000}if\sexist\s.{0,1000}\.txt\secho\sImHere.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string6 = /.{0,1000}install\ssmbmap.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string7 = /.{0,1000}install\ssmbmap.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string8 = /.{0,1000}ShawnDEvans\/smbmap.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string9 = /.{0,1000}smbmap\s\-.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string10 = /.{0,1000}smbmap\.py\s.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string11 = /.{0,1000}smbmap\.smbmap.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string12 = /.{0,1000}smbmap\-master.{0,1000}/ nocase ascii wide
        // Description: SMBMap allows users to enumerate samba share drives across an entire domain. List share drives. drive permissions. share contents. upload/download functionality. file name auto-download pattern matching. and even execute remote commands. This tool was designed with pen testing in mind. and is intended to simplify searching for potentially sensitive data across large networks.
        // Reference: https://github.com/ShawnDEvans/smbmap
        $string13 = /.{0,1000}\-x\s.{0,1000}net\sgroup\s.{0,1000}Domain\sAdmins.{0,1000}\s\/domain.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
