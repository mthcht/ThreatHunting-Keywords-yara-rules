rule TunnelVision
{
    meta:
        description = "Detection patterns for the tool 'TunnelVision' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TunnelVision"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string1 = /\sconfigdhcpserver\.sh/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string2 = /\sdhcpd\-noroute\.conf/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string3 = /\snorouteconfig\.sh/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string4 = /\sTunnelVisionVM\.ova/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string5 = /\/configdhcpserver\.sh/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string6 = /\/dhcpd\-noroute\.conf/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string7 = /\/norouteconfig\.sh/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string8 = /\/TunnelVision\.git/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string9 = /\/TunnelVisionVM\.ova/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string10 = /\\TunnelVision\-main/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string11 = /\\TunnelVisionVM\.ova/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string12 = /354a7236afe220e7c831129fbf32434edd1d18961118dfb05279ff5c1b6f38ad/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string13 = /5176f4cdb10d1261d0327e76daf563a5dcc4e32b8556da761620bc1d467f002e/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string14 = /apt\-get\sinstall\sisc\-dhcp\-server\snet\-tools/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string15 = /d1b43d39823d14ec9524f63fa0125ad9606d5c3e32d8e10d34a25214c56d308f/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string16 = /d3fcbfcd8d9ca33ba19dffbcc8d5de2f8ef18baa028e41eded243a84d496e8d8/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string17 = /d987f5f570ddac113c3083de784aac66b7550f639fb0cdd6d88bed99ae21821c/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string18 = /https\:\/\/drive\.google\.com\/file\/d\/1WLJGs3ZUypf6hLh5WL4AJmsKdUOZo5yZ/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string19 = /Installing\sDHCP\sserver\sand\snet\-tools/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string20 = /journalctl\s\-u\sisc\-dhcp\-server\.service\s\|\stail\s\-n\s50/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string21 = /leviathansecurity\/TunnelVision/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string22 = /Replacing\s\/etc\/dhcp\/dhcpd\.conf\swith\sno\sroute\spush\sconfig/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string23 = /sudo\s\.\/startup\.sh/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string24 = /TunnelVision\/pushrouteconfig\.sh/ nocase ascii wide
        // Description: TunnelVision uses DHCP option 121 to manipulate routing tables and decloak VPN traffic
        // Reference: https://github.com/leviathansecurity/TunnelVision
        $string25 = /www\.leviathansecurity\.com\/blog\/tunnelvision/ nocase ascii wide
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
