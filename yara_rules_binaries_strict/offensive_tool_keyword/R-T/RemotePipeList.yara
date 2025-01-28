rule RemotePipeList
{
    meta:
        description = "Detection patterns for the tool 'RemotePipeList' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemotePipeList"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string1 = /\[\+\]\sConnected\sto\s\\\\\\\\.{0,100}\\\\IPC\$/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string2 = /\[\+\]\sPipe\slisting\:/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string3 = "70BCFFDB-AE25-4BEA-BF0E-09DF06B7DBC4" nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string4 = /beacon_command_detail\(\\"remotepipelist\\"/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string5 = "List the named pipes on a remote system" nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string6 = "namespace RemotePipeList" nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string7 = /outflank_stage1\.implant/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string8 = "remotepipelist " nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string9 = "RemotePipeList is x64 only" nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string10 = /RemotePipeList\.cna/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string11 = /RemotePipeList\.exe/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string12 = /stage1\-remotepipelist\.py/ nocase ascii wide
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
