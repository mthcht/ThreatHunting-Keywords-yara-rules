rule assoc
{
    meta:
        description = "Detection patterns for the tool 'assoc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "assoc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: will return the file association for file extensions that include the string =cm - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string1 = /.{0,1000}assoc\s.{0,1000}findstr\s.{0,1000}\=cm.{0,1000}/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string lCmd - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string2 = /.{0,1000}assoc\s.{0,1000}findstr\s.{0,1000}lCmd.{0,1000}/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string mdf - hidden objectif is to find cmdfile association
        // Reference: N/A
        $string3 = /.{0,1000}assoc\s.{0,1000}findstr\s.{0,1000}mdf.{0,1000}/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string s1x - hidden objectif is to find .ps1xml association
        // Reference: N/A
        $string4 = /.{0,1000}assoc\s.{0,1000}findstr\s.{0,1000}s1x.{0,1000}/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string =cm - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string5 = /.{0,1000}assoc\s.{0,1000}findstr\s\=cm.{0,1000}/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string lCmd - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string6 = /.{0,1000}assoc\s.{0,1000}findstr\slCmd.{0,1000}/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string mdf - hidden objectif is to find cmdfile association
        // Reference: N/A
        $string7 = /.{0,1000}assoc\s.{0,1000}findstr\smdf.{0,1000}/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string s1x - hidden objectif is to find .ps1xml association
        // Reference: N/A
        $string8 = /.{0,1000}assoc\s.{0,1000}findstr\ss1x.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
