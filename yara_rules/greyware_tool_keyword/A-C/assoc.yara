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
        $string1 = /assoc\s.{0,1000}findstr\s.{0,1000}\=cm/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string lCmd - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string2 = /assoc\s.{0,1000}findstr\s.{0,1000}lCmd/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string mdf - hidden objectif is to find cmdfile association
        // Reference: N/A
        $string3 = /assoc\s.{0,1000}findstr\s.{0,1000}mdf/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string s1x - hidden objectif is to find .ps1xml association
        // Reference: N/A
        $string4 = /assoc\s.{0,1000}findstr\s.{0,1000}s1x/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string =cm - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string5 = /assoc\s.{0,1000}findstr\s\=cm/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string lCmd - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string6 = /assoc\s.{0,1000}findstr\slCmd/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string mdf - hidden objectif is to find cmdfile association
        // Reference: N/A
        $string7 = /assoc\s.{0,1000}findstr\smdf/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string s1x - hidden objectif is to find .ps1xml association
        // Reference: N/A
        $string8 = /assoc\s.{0,1000}findstr\ss1x/ nocase ascii wide

    condition:
        any of them
}
