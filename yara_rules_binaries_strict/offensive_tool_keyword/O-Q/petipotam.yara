rule petipotam
{
    meta:
        description = "Detection patterns for the tool 'petipotam' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "petipotam"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string1 = /\/PetitPotam\.exe/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string2 = /\/PetitPotam\.git/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string3 = /\[\-\]\sGot\sRPC_ACCESS_DENIED\!\!\sEfsRpcOpenFileRaw\sis\sprobably\sPATCHED\!/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string4 = /\\PetitPotam\.exe/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string5 = "3989cbea4af22774f0fa20d10b88c7247e675be8b9ec9dae716a44cb36d50189" nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string6 = "D78924E1-7F2B-4315-A2D2-24124C7828F8" nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string7 = /GILLES\sLionel\saka\stopotam\s\(\@topotam77\)/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string8 = /PetitPotam\.cpp/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string9 = /PetitPotam\.exe/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string10 = /PetitPotam\.py/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string11 = /PetitPotam\.sln/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string12 = "PetitPotam:main" nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string13 = /topotam\.exe/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string14 = "topotam/PetitPotam" nocase ascii wide
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
