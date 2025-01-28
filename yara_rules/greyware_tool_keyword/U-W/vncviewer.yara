rule vncviewer
{
    meta:
        description = "Detection patterns for the tool 'vncviewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vncviewer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: VNCViewer is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: N/A
        $string1 = ">RealVNC<" nocase ascii wide
        // Description: VNCViewer is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: N/A
        $string2 = ">UltraVNC VNCViewer<" nocase ascii wide
        // Description: SimpleHelp or VNCViewer is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: simple-help.com
        $string3 = /ProgramData\\JWrapper\-Remote\sAccess\\.{0,1000}\.exe/ nocase ascii wide
        // Description: VNCViewer is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: N/A
        $string4 = /RealVNC\.VNCViewer/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string5 = /vncviewer\s.{0,1000}\..{0,1000}\:5901/
        // Description: VNCViewer is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: N/A
        $string6 = /VNCViewer\.exe/ nocase ascii wide

    condition:
        any of them
}
