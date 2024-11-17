rule C2_Tool_Collection
{
    meta:
        description = "Detection patterns for the tool 'C2-Tool-Collection' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2-Tool-Collection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string1 = /\/C2\-Tool\-Collection\// nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string2 = /\/SprayAD\.exe/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string3 = /\\SprayAD\.cna/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string4 = /\\SprayAD\.exe/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string5 = /Lapsdump\.cna/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string6 = /Lapsdump\.exe/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string7 = /PetitPotam\.cna/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string8 = /PetitPotam\.exe/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string9 = /PetitPotam\.ps1/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string10 = /PetitPotam\.sln/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string11 = /PetitPotam\.vcxproj/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string12 = /ReflectiveDll\./ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string13 = /ReflectiveDLLInjection\./ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string14 = /ReflectiveLoader\./ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string15 = /SprayAD\.exe\s/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string16 = /TicketToHashcat\.py/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string17 = /Lapsdump\s/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string18 = /SprayAD\s.{0,100}\s.{0,100}\s/ nocase ascii wide
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
