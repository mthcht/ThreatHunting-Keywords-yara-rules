rule attifyos
{
    meta:
        description = "Detection patterns for the tool 'attifyos' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "attifyos"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AttifyOS is a distro intended to help you perform security assessment and penetration testing of Internet of Things (IoT) devices. It saves you a lot of time by providing a pre-configured environment with all the necessary tools loaded. The new version is based on Ubuntu 18.04 64-Bit - that also means that you'll receive updates for this version till April 2023.
        // Reference: https://github.com/adi0x90/attifyos
        $string1 = /AttifyOS/ nocase ascii wide

    condition:
        any of them
}
