rule CMLoot
{
    meta:
        description = "Detection patterns for the tool 'CMLoot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CMLoot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string1 = /\sCMLoot\.ps1/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string2 = /\s\-SCCMHost\s.{0,1000}\s\-Outfile\s/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string3 = /\/CMLoot\.git/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string4 = /\/CMLoot\.ps1/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string5 = /\\CMLoot\.ps1/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string6 = /1njected\/CMLoot/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string7 = /CMLoot\.psm1/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string8 = /CMLoot\-main/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string9 = /Invoke\-CMLootDownload/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string10 = /Invoke\-CMLootExtract/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string11 = /Invoke\-CMLootHunt\s/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string12 = /Invoke\-CMLootInventory/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string13 = /src\\CMLootOut\\/ nocase ascii wide

    condition:
        any of them
}
