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
        $string1 = /\\system32\.zip/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string2 = /ntdsutil\s.*ac\si\sntds.*\s.*create\sfull.*\\temp/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string3 = /ntdsutil\.exe\s.*ac\si\sntds.*\s.*ifm.*\s.*create\sfull\s.*c:\\ProgramData/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string4 = /ntdsutil\.exe\s.*ac\si\sntds.*\s.*ifm.*\s.*create\sfull\s.*users\\public/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string5 = /ntdsutil\.exe\s.*ac\si\sntds.*ifm.*create\sfull\s.*temp/ nocase ascii wide

    condition:
        any of them
}