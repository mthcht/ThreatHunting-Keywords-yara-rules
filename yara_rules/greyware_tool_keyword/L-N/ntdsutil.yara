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
        // Description: Misuse of this command could indicate an attempt to transfer or seize FSMO roles which are critical for Active Directory operations
        // Reference: N/A
        $string2 = /ntdsutil\s\"ac\sin\sntds\"\sroles/ nocase ascii wide
        // Description: An attacker could use this to revert changes in AD for persistence
        // Reference: N/A
        $string3 = /ntdsutil\s\"activate\sinstance\sntds\"\sauthoritative\srestore/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string4 = /ntdsutil\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}create\sfull.{0,1000}\\temp/ nocase ascii wide
        // Description: create an installation media set from the NTDS database (Install From Media). This could be abused to exfiltrate the Active Directory database for offline attacks or manipulation.
        // Reference: N/A
        $string5 = /ntdsutil\s.{0,1000}activate\sinstance\sntds.{0,1000}\sifm/ nocase ascii wide
        // Description: An attacker might use this command to manipulate or inspect the AD database files
        // Reference: N/A
        $string6 = /ntdsutil\sfiles/ nocase ascii wide
        // Description: could indicate an attempt to manipulate the directory's metadata
        // Reference: N/A
        $string7 = /ntdsutil\smetadata\scleanup/ nocase ascii wide
        // Description: Attackers could abuse this to manipulate directory partitions
        // Reference: N/A
        $string8 = /ntdsutil\spartition\smanagement/ nocase ascii wide
        // Description: Snapshots contain a copy of the AD database and attackers may use it to obtain sensitive information
        // Reference: N/A
        $string9 = /ntdsutil\ssnapshot/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string10 = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}ifm.{0,1000}\s.{0,1000}create\sfull\s.{0,1000}c\:\\ProgramData/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string11 = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}ifm.{0,1000}\s.{0,1000}create\sfull\s.{0,1000}users\\public/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string12 = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}ifm.{0,1000}create\sfull\s.{0,1000}temp/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string13 = /The\sdatabase\sengine\screated\sa\snew\sdatabase.{0,1000}temp\\Active\sDirectory\\ntds\.dit/ nocase ascii wide

    condition:
        any of them
}
