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
        // Description: hide evidence of RDP connections
        // Reference: https://github.com/xiaoy-sec/Pentest_Note/blob/52156f816f0c2497c25343c2e872130193acca80/wiki/%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87/Windows%E6%8F%90%E6%9D%83/RDP%26Firewall/%E5%88%A0%E9%99%A4%E7%97%95%E8%BF%B9.md?plain=1#L4
        $string2 = /attrib\s.{0,1000}\.rdp\s\-s\s\-h/ nocase ascii wide
        // Description: suspicious attrib command
        // Reference: https://github.com/petikvx/vx-ezine/blob/cfaf09bb089a08a9f33254929209fb32ebd52806/darkcodes/dc1/Sources/Sph1nX_Sources/DeskLock/DeskLock.txt#L13
        $string3 = /attrib\s\+R\s\+S\s\+H\sC\:\\WINDOWS\\scvhost\.exe/ nocase ascii wide
        // Description: defense evasion - hidding in suspicious directory
        // Reference: N/A
        $string4 = /attrib\s\+s\s\+h\s\/D\s\\"C\:\\Program\sFiles\\Windows\sNT\\/ nocase ascii wide
        // Description: defense evasion - hidding in suspicious directory
        // Reference: N/A
        $string5 = /attrib\s\+s\s\+h\s\/D\s\\"C\:\\users\\Public\\/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string6 = /attrib\s\+s\s\+h\sdesktop\.ini/ nocase ascii wide
        // Description: suspicious attrib command
        // Reference: https://github.com/petikvx/vx-ezine/blob/cfaf09bb089a08a9f33254929209fb32ebd52806/darkcodes/dc1/Sources/Sph1nX_Sources/DeskLock/DeskLock.txt#L13
        $string7 = /attrib\s\-R\s\-S\s\-H\sC\:\\WINDOWS\\explorer\.exe/ nocase ascii wide
        // Description: suspicious attrib command
        // Reference: https://github.com/petikvx/vx-ezine/blob/cfaf09bb089a08a9f33254929209fb32ebd52806/darkcodes/dc1/Sources/Sph1nX_Sources/DeskLock/DeskLock.txt#L13
        $string8 = /attrib\s\-R\s\-S\s\-H\sC\:\\WINDOWS\\System32\\explorer\.exe/ nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string9 = "attrib -s -h %userprofile%" nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string10 = /attrib\s\-s\s\-h\s\%userprofile\%\\documents\\Default\.rdp/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string11 = /echo\s\[\.ShellClassInfo\]\s\>\sdesktop\.ini/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string12 = /echo\sIconResource\=\\\\.{0,1000}\\.{0,1000}\s\>\>\sdesktop\.ini/ nocase ascii wide

    condition:
        any of them
}
