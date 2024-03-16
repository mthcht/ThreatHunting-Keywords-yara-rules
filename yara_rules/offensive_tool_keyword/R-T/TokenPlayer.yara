rule TokenPlayer
{
    meta:
        description = "Detection patterns for the tool 'TokenPlayer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenPlayer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string1 = /\s\-\-maketoken\s\-\-username\s.{0,1000}\s\-\-password\s.{0,1000}\s\-\-domain\s/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string2 = /\s\-\-spoofppid\s\-\-ppid\s/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string3 = /\sUAC\-TokenMagic\.ps1/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string4 = /\.exe\s\-\-exec\s\-\-pid\s.{0,1000}\s\-\-prog\s.{0,1000}cmd\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string5 = /\.exe\s\-\-impersonate\s\-\-pid\s/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string6 = /\/TokenPlayer\.git/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string7 = /\/UAC\-TokenMagic\.ps1/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string8 = /\[\+\]ImpersonateLoggedOnUser\(\)\ssucceed\!/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string9 = /\\ProcessSpoofing\.h/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string10 = /\\TokenPlayer\.cpp/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string11 = /\\TokenPlayer\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string12 = /\\TokenPlayer\\TokenPlayer\\/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string13 = /\\UAC\-TokenMagic\.ps1/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string14 = /\]Spawning\sProcess\swith\sSpoofed\sParent/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string15 = /0ADFD1F0\-7C15\-4A22\-87B4\-F67E046ECD96/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string16 = /95d19ae58bbd6b38b4988fae5c7b514c8451a15e940f1392bcf1f93374364054/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string17 = /S1ckB0y1337\/TokenPlayer/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string18 = /TokenPlayer\-v0\.3\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string19 = /TokenPlayer\-v0\.4\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string20 = /TokenPlayer\-v0\.5\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string21 = /TokenPlayer\-v0\.6\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string22 = /TokenPlayer\-v0\.7\.exe/ nocase ascii wide
        // Description: Manipulating and Abusing Windows Access Tokens
        // Reference: https://github.com/S1ckB0y1337/TokenPlayer
        $string23 = /TokenPlayer\-v0\.8\.exe/ nocase ascii wide

    condition:
        any of them
}
