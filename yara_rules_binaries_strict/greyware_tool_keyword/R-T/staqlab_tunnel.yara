rule staqlab_tunnel
{
    meta:
        description = "Detection patterns for the tool 'staqlab-tunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "staqlab-tunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Expose localhost to internet
        // Reference: https://github.com/cocoflan/Staqlab-tunnel
        $string1 = /\.\/staqlab\-tunnel\s/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/cocoflan/Staqlab-tunnel
        $string2 = "/bin/staqlab-tunnel" nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/cocoflan/Staqlab-tunnel
        $string3 = "6510fdf42becdab665232ef6393e40a559dd2b3b2b7927333c9f30a62bf7de3f" nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/cocoflan/Staqlab-tunnel
        $string4 = "7ec426ac53bac81654965fa1b8ff8af3451b7524f648d4b11ea7d3437a5ba907" nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/cocoflan/Staqlab-tunnel
        $string5 = "d0d66c649a64735a67735370f0790418b48abeccaa0506fa66f00a967e8c3b73" nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/cocoflan/Staqlab-tunnel
        $string6 = "staqlab-tunnel port=" nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/cocoflan/Staqlab-tunnel
        $string7 = /staqlab\-tunnel\.exe/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/cocoflan/Staqlab-tunnel
        $string8 = /staqlab\-tunnel\.zip/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/cocoflan/Staqlab-tunnel
        $string9 = /tunnel\.staqlab\.com/ nocase ascii wide
        // Description: Expose localhost to internet
        // Reference: https://github.com/cocoflan/Staqlab-tunnel
        $string10 = /tunnel\-api\.staqlab\.com/ nocase ascii wide
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
