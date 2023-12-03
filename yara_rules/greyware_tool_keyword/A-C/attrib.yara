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
        $string1 = /.{0,1000}\\attrib\.exe.{0,1000}\s\+H\s.{0,1000}/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string2 = /.{0,1000}attrib\s\+s\s\+h\sdesktop\.ini.{0,1000}/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string3 = /.{0,1000}echo\s\[\.ShellClassInfo\]\s\>\sdesktop\.ini.{0,1000}/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string4 = /.{0,1000}echo\sIconResource\=\\\\.{0,1000}\\.{0,1000}\s\>\>\sdesktop\.ini.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
