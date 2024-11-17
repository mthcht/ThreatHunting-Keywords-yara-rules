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
        $string2 = /ntdsutil\s\\"ac\sin\sntds\\"\sroles/ nocase ascii wide
        // Description: An attacker could use this to revert changes in AD for persistence
        // Reference: N/A
        $string3 = /ntdsutil\s\\"activate\sinstance\sntds\\"\sauthoritative\srestore/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string4 = /ntdsutil\s.{0,100}ac\si\sntds.{0,100}\s.{0,100}create\sfull.{0,100}\\temp/ nocase ascii wide
        // Description: create an installation media set from the NTDS database (Install From Media). This could be abused to exfiltrate the Active Directory database for offline attacks or manipulation.
        // Reference: N/A
        $string5 = /ntdsutil\s.{0,100}activate\sinstance\sntds.{0,100}\sifm/ nocase ascii wide
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
        $string10 = /ntdsutil\.exe\s.{0,100}ac\si\sntds.{0,100}\s.{0,100}ifm.{0,100}\s.{0,100}create\sfull\s.{0,100}c\:\\ProgramData/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string11 = /ntdsutil\.exe\s.{0,100}ac\si\sntds.{0,100}\s.{0,100}ifm.{0,100}\s.{0,100}create\sfull\s.{0,100}users\\public/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string12 = /ntdsutil\.exe\s.{0,100}ac\si\sntds.{0,100}ifm.{0,100}create\sfull\s.{0,100}temp/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string13 = /The\sdatabase\sengine\screated\sa\snew\sdatabase.{0,100}temp\\Active\sDirectory\\ntds\.dit/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
