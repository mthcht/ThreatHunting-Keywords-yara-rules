rule vncviewer
{
    meta:
        description = "Detection patterns for the tool 'vncviewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vncviewer"
        rule_category = "signature_keyword"

    strings:
        // Description: VNCViewer is an RMM tool that has been exploited by attackers to gain unauthorized remote access 
        // Reference: N/A
        $string1 = "RemoteAccess:Win32/RealVNC" nocase ascii wide

    condition:
        any of them
}
