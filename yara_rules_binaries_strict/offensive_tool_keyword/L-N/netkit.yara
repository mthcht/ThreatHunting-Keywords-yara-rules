rule netkit
{
    meta:
        description = "Detection patterns for the tool 'netkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string1 = /\/netkit\.git/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string2 = /\/netkit\/client\/shell\.py/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string3 = /\/netkit\/src\/netkit\./ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string4 = /\[\+\]\ssuccessfully\sself\sdestructed\sserver/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string5 = /\\netkit\\client\\shell\.py/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string6 = /\\netkit\\src\\netkit\./ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string7 = "8dece0ec5b60725419e384b317c5be3c15d3cc12c1c7da28a53ec344118f9cd9" nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string8 = "CONFIG_NETKIT_DEBUG" nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string9 = /ls\s\-la\snetkit\.ko/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string10 = /NETKIT_LOG\(\\"/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string11 = /NETKIT_XOR\\x00/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string12 = "Notselwyn/netkit" nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string13 = /run_kmod\.sh\snetkit\.ko\snetkit/
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string14 = /run_python\.sh\sclient\/shell\.py/
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
