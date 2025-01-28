rule nimplant
{
    meta:
        description = "Detection patterns for the tool 'nimplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimplant"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string1 = " -d:sleepmask" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string2 = " exe-selfdelete" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string3 = " --nomain -d:exportDll --passL:" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string4 = /\.nimplant/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string5 = /\.ShellcodeRDI/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string6 = /\/NimPlant\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string7 = "/NimPlant/" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string8 = "/nimplants/" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string9 = /\\NimPlant\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string10 = "_nimplant_" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string11 = /127\.0\.0\.1\:31337/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string12 = "789CF3CBCC0DC849CC2B51703652084E2D2A4B2D02003B5C0650" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string13 = "BeaconGetSpawnTo" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string14 = "BeaconInjectProcess" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string15 = "C2 Client" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string16 = "C2 Nimplant Server" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string17 = "Cannot enumerate antivirus" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string18 = "chvancooten/nimbuild" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string19 = "chvancooten/NimPlant" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string20 = /Cmd\-Execute\-Assembly\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string21 = /Cmd\-Inline\-Execute\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string22 = /Cmd\-Shinject\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string23 = /Cmd\-Upload\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string24 = "compile_implant" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string25 = "ConvertToShellcode" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string26 = "dbGetNimplant" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string27 = /details\-c80a6994018b23dc\.js/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string28 = "EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQj" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string29 = "execute-assembly " nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string30 = /executeAssembly\.nim/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string31 = /f4081a8e30f75d46\.js/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string32 = /fde1b109f9704ff7\.css/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string33 = "getNimplantByGuid" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string34 = "getPositionImplant" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string35 = "import np_server" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string36 = /inline\-execute\s.{0,100}\.o/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string37 = /inlineExecute\.nim/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string38 = "killAllNimplants" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string39 = "localhost:31337" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string40 = "NimPlant v" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string41 = "nimplant-" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string42 = /NimPlant.{0,100}\.tar\.gz/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string43 = /NimPlant.{0,100}\.zip/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string44 = /nimplant\.db/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string45 = /NimPlant\.dll/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string46 = /NimPlant\.nim/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string47 = /NimPlant\.nimble/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string48 = /NimPlant\.py/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string49 = "nimplantPrint" nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string50 = /nimplants\-.{0,100}\.js/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string51 = /nimplants\.html/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string52 = /\-selfdelete\.exe\s\-d\:selfdelete/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string53 = /server\-7566091c4e4a2a24\.js/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string54 = /shell\s\'cmd\.exe\s\/c/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string55 = /ShellcodeRDI\.py/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string56 = "shinject " nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string57 = /shinject\.nim/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string58 = /util\.nimplant/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string59 = /whoami\.nim/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string60 = /zippy\.nim/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
