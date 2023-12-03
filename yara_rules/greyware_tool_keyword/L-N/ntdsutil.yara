rule ntdsutil
{
    meta:
        description = "Detection patterns for the tool 'ntdsutil' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdsutil"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string1 = /.{0,1000}\\system32\.zip.{0,1000}/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string2 = /.{0,1000}ntdsutil\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}create\sfull.{0,1000}\\temp.{0,1000}/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string3 = /.{0,1000}ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}ifm.{0,1000}\s.{0,1000}create\sfull\s.{0,1000}c:\\ProgramData.{0,1000}/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string4 = /.{0,1000}ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}ifm.{0,1000}\s.{0,1000}create\sfull\s.{0,1000}users\\public.{0,1000}/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string5 = /.{0,1000}ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}ifm.{0,1000}create\sfull\s.{0,1000}temp.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
