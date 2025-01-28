rule Disk2vhd
{
    meta:
        description = "Detection patterns for the tool 'Disk2vhd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Disk2vhd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: convert physical disks into Virtual Hard Disk (VHD) files -attackers can leverage it for Collection
        // Reference: N/A
        $string1 = ">Disk to VHD converter<" nocase ascii wide
        // Description: convert physical disks into Virtual Hard Disk (VHD) files -attackers can leverage it for Collection
        // Reference: N/A
        $string2 = ">Disk2vhd<" nocase ascii wide
        // Description: convert physical disks into Virtual Hard Disk (VHD) files -attackers can leverage it for Collection
        // Reference: N/A
        $string3 = /disk2vhd\.exe/ nocase ascii wide
        // Description: convert physical disks into Virtual Hard Disk (VHD) files -attackers can leverage it for Collection
        // Reference: N/A
        $string4 = /Disk2vhd\.zip/ nocase ascii wide
        // Description: convert physical disks into Virtual Hard Disk (VHD) files -attackers can leverage it for Collection
        // Reference: N/A
        $string5 = /disk2vhd64\.exe/ nocase ascii wide

    condition:
        any of them
}
