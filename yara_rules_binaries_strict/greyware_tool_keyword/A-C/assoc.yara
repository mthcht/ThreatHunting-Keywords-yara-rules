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
        $string1 = /assoc\s.{0,100}findstr\s.{0,100}\=cm/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string lCmd - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string2 = /assoc\s.{0,100}findstr\s.{0,100}lCmd/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string mdf - hidden objectif is to find cmdfile association
        // Reference: N/A
        $string3 = /assoc\s.{0,100}findstr\s.{0,100}mdf/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string s1x - hidden objectif is to find .ps1xml association
        // Reference: N/A
        $string4 = /assoc\s.{0,100}findstr\s.{0,100}s1x/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string =cm - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string5 = /assoc\s.{0,100}findstr\s\=cm/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string lCmd - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string6 = /assoc\s.{0,100}findstr\slCmd/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string mdf - hidden objectif is to find cmdfile association
        // Reference: N/A
        $string7 = /assoc\s.{0,100}findstr\smdf/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string s1x - hidden objectif is to find .ps1xml association
        // Reference: N/A
        $string8 = /assoc\s.{0,100}findstr\ss1x/ nocase ascii wide
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
