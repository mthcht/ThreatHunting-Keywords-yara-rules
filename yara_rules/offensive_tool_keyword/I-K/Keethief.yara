rule Keethief
{
    meta:
        description = "Detection patterns for the tool 'Keethief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Keethief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string1 = /.{0,1000}Add\-KeePassConfigTrigger.{0,1000}/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string2 = /.{0,1000}Find\-KeePassconfig.{0,1000}/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string3 = /.{0,1000}Get\-KeePassConfigTrigger.{0,1000}/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string4 = /.{0,1000}Get\-KeePassDatabaseKey.{0,1000}/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string5 = /.{0,1000}Get\-PEHeader\.ps1.{0,1000}/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string6 = /.{0,1000}KcpPassword\.cs.{0,1000}/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string7 = /.{0,1000}KeePass\.sln.{0,1000}/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string8 = /.{0,1000}KeePassConfig\.ps1.{0,1000}/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string9 = /.{0,1000}KeeThief.{0,1000}/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string10 = /.{0,1000}Remove\-KeePassConfigTrigger.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
