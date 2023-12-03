rule Hijacker
{
    meta:
        description = "Detection patterns for the tool 'Hijacker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hijacker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hijacker is a Graphical User Interface for the penetration testing tools Aircrack-ng. Airodump-ng. MDK3 and Reaver. It offers a simple and easy UI to use these tools without typing commands in a console and copy&pasting MAC addresses.This application requires an ARM android device with an internal wireless adapter that supports Monitor Mode. A few android devices do. but none of them natively. This means that you will need a custom firmware. Any device that uses the BCM4339 chipset (MSM8974. such as Nexus 5. Xperia Z1/Z2. LG G2. LG G Flex. Samsung Galaxy Note 3) will work with Nexmon (which also supports some other chipsets). Devices that use BCM4330 can use bcmon.
        // Reference: https://github.com/chrisk44/Hijacker
        $string1 = /.{0,1000}Hijacker.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
