rule PPLmedic
{
    meta:
        description = "Detection patterns for the tool 'PPLmedic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLmedic"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string1 = /\sPPLmedic\.exe/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string2 = /\/PPLmedic\.exe/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string3 = /\/PPLmedic\.git/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string4 = /\[\+\]\sPayload\sDLL\ssuccessfully\sloaded\safter/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string5 = /\\\\PPLmedic\\\\ntstuff/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string6 = /\\ExploitElevate\.cpp/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string7 = /\\PPLmedic\.cpp/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string8 = /\\PPLmedic\.exe/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string9 = /\\PPLmedic\\PPLmedic/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string10 = /\\Temp\\csrss\.dmp/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string11 = /\\Temp\\lsass\.dmp/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string12 = /29CBBC24\-363F\-42D7\-B018\-5EF068BA8777/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string13 = /4d2f66539f067f631db31039ec81707028bb37efcd2ebbf86a1a920d60d75263/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string14 = /ac49d2041cd57b1efba672c3305b621ebb265380010b8951cda01c055a7e1e64/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string15 = /db03400af112a7969ba2d68288b9dc908b2d234d62184fd5f01079749c4bf09e/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string16 = /F00A3B5F\-D9A9\-4582\-BBCE\-FD10EFBF0C17/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string17 = /fa06c45e4522706565bea7e2532ba67cf2cad3e57e38157c09e46445c1dd100a/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string18 = /itm4n\/PPLmedic/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string19 = /PPLmedicDll\.def/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string20 = /PPLmedicDll\.dll/ nocase ascii wide
        // Description: Dump the memory of any PPL with a Userland exploit chain
        // Reference: https://github.com/itm4n/PPLmedic
        $string21 = /WaaSMedicPayload\.dll/ nocase ascii wide
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
