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
        $string7 = /8dece0ec5b60725419e384b317c5be3c15d3cc12c1c7da28a53ec344118f9cd9/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string8 = /CONFIG_NETKIT_DEBUG/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string9 = /ls\s\-la\snetkit\.ko/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string10 = /NETKIT_LOG\(\"/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string11 = /NETKIT_XOR\\x00/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string12 = /Notselwyn\/netkit/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string13 = /run_kmod\.sh\snetkit\.ko\snetkit/ nocase ascii wide
        // Description: Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.
        // Reference: https://github.com/Notselwyn/netkit
        $string14 = /run_python\.sh\sclient\/shell\.py/ nocase ascii wide

    condition:
        any of them
}
