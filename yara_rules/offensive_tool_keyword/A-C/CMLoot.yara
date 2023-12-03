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
        $string1 = /.{0,1000}\sCMLoot\.ps1.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string2 = /.{0,1000}\s\-SCCMHost\s.{0,1000}\s\-Outfile\s.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string3 = /.{0,1000}\/CMLoot\.git.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string4 = /.{0,1000}\/CMLoot\.ps1.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string5 = /.{0,1000}\\CMLoot\.ps1.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string6 = /.{0,1000}1njected\/CMLoot.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string7 = /.{0,1000}CMLoot\.psm1.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string8 = /.{0,1000}CMLoot\-main.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string9 = /.{0,1000}Invoke\-CMLootDownload.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string10 = /.{0,1000}Invoke\-CMLootExtract.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string11 = /.{0,1000}Invoke\-CMLootHunt\s.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string12 = /.{0,1000}Invoke\-CMLootInventory.{0,1000}/ nocase ascii wide
        // Description: Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares
        // Reference: https://github.com/1njected/CMLoot
        $string13 = /.{0,1000}src\\CMLootOut\\.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
