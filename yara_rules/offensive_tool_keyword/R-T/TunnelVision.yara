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

    condition:
        any of them
}
