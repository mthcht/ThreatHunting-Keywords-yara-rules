rule physmem2profit
{
    meta:
        description = "Detection patterns for the tool 'physmem2profit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "physmem2profit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string1 = /\sphysmem2minidump\.py/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string2 = /\/label\-date\-lsass\.dmp/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string3 = /\/physmem2minidump\.py/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string4 = /\/physmem2profit\.git/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string5 = /\\physmem2minidump\.py/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string6 = /\\physmem2profit\-master/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string7 = ">physmem2profit<" nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string8 = "23ecca2af6db4c425ab534b9a738f7ec152c7fcf3c250f3ce9d7f57e6259eac9" nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string9 = "814708C9-2320-42D2-A45F-31E42DA06A94" nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string10 = "cc24850f03dccbd8ee3a372b06b2a77a95e5314bb68d2483b1814935978b7003" nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string11 = "MimikatzStream should be at offset " nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string12 = /output.{0,100}\-lsass\.dmp/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string13 = /physmem2profit\.exe/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string14 = /Physmem2profit\.sln/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string15 = /physmem2profit\-public\.zip/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string16 = "source physmem2profit" nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string17 = "WithSecureLabs/physmem2profit" nocase ascii wide
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
