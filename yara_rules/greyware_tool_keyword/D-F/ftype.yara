rule ftype
{
    meta:
        description = "Detection patterns for the tool 'ftype' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ftype"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: will return the file type information for file types that include the string dfil - hidden objectif is to find cmdfile string
        // Reference: N/A
        $string1 = /ftype\s.{0,1000}findstr\s.{0,1000}dfil/ nocase ascii wide
        // Description: will return the file type information for file types that include the string SHCm - hidden objectif is to find SHCmdFile string
        // Reference: N/A
        $string2 = /ftype\s.{0,1000}findstr\s.{0,1000}SHCm/ nocase ascii wide
        // Description: will return the file type information for file types that include the string dfil - hidden objectif is to find cmdfile string
        // Reference: N/A
        $string3 = /ftype\s.{0,1000}findstr\sdfil/ nocase ascii wide
        // Description: will return the file type information for file types that include the string SHCm - hidden objectif is to find SHCmdFile string
        // Reference: N/A
        $string4 = /ftype\s.{0,1000}findstr\sSHCm/ nocase ascii wide

    condition:
        any of them
}
