rule SchTask_0x727
{
    meta:
        description = "Detection patterns for the tool 'SchTask_0x727' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SchTask_0x727"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string1 = /\/SchTask\.zip/ nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string2 = /\/SchTask_0x727\.git/ nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string3 = "/SchTask_0x727/" nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string4 = /\\bin\\Release\\SchTask\.exe/ nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string5 = /\\SchTask\.sln/ nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string6 = /\\SchTask\.zip/ nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string7 = /\\SchTask_0x727\\/ nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string8 = /\]\sHidden\stask\sxml\sfile\:\s/ nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string9 = "0790530e1e0f1ed73b2b6fd701d75a2409c785af5367304d5fdd5bdfdf7eae46" nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string10 = "0x727/SchTask_0x727" nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string11 = "24aae23bcf8b0a513988d69b1526eebd791007136a1faf08ea1df5a8d3884e50" nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string12 = "70c104eb31780222a3a882a3728cafeeb308d8ff718a5c9ce62778d579b3de86" nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string13 = "b26b8713dc24bec3c5b0be456a1bbc058a8450c280d614695a691fa13ac6dbfd" nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string14 = "E61C950E-A03D-40E2-AAD5-304C48570364" nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string15 = "fe1ae959f9af863a11cefad541eb791a01e5bb9931cf5c57e478236ddad92ae6" nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string16 = /SchTask\.exe\sC\:\\Windows\\System32\\cmd\.exe\s/ nocase ascii wide
        // Description: create hidden scheduled tasks
        // Reference: https://github.com/0x727/SchTask_0x727
        $string17 = "SchTask_0x727/releases" nocase ascii wide
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
