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
        $string1 = /Add\-KeePassConfigTrigger/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string2 = /Find\-KeePassconfig/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string3 = /Get\-KeePassConfigTrigger/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string4 = /Get\-KeePassDatabaseKey/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string5 = /Get\-PEHeader\.ps1/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string6 = /KcpPassword\.cs/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string7 = /KeePass\.sln/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string8 = /KeePassConfig\.ps1/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string9 = /KeeThief/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string10 = /Remove\-KeePassConfigTrigger/ nocase ascii wide

    condition:
        any of them
}
