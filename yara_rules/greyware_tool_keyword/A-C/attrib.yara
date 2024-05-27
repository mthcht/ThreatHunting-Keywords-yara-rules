rule attrib
{
    meta:
        description = "Detection patterns for the tool 'attrib' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "attrib"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: command aiming to hide a file.  It can be performed with attrib.exe on a WINDOWS machine with command option +h 
        // Reference: N/A
        $string1 = /\\attrib\.exe.{0,1000}\s\+H\s/ nocase ascii wide
        // Description: defense evasion - hidding in suspicious directory
        // Reference: N/A
        $string2 = /attrib\s\+s\s\+h\s\/D\s\"C\:\\Program\sFiles\\Windows\sNT\\/ nocase ascii wide
        // Description: defense evasion - hidding in suspicious directory
        // Reference: N/A
        $string3 = /attrib\s\+s\s\+h\s\/D\s\"C\:\\users\\Public\\/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string4 = /attrib\s\+s\s\+h\sdesktop\.ini/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string5 = /echo\s\[\.ShellClassInfo\]\s\>\sdesktop\.ini/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string6 = /echo\sIconResource\=\\\\.{0,1000}\\.{0,1000}\s\>\>\sdesktop\.ini/ nocase ascii wide

    condition:
        any of them
}
