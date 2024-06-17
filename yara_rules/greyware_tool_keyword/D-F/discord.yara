rule discord
{
    meta:
        description = "Detection patterns for the tool 'discord' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "discord"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Downloading discord executables and archives attachments
        // Reference: N/A
        $string1 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.bat/ nocase ascii wide
        // Description: Downloading discord executables and archives attachments
        // Reference: N/A
        $string2 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Downloading discord executables and archives attachments
        // Reference: N/A
        $string3 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.hta/ nocase ascii wide
        // Description: Downloading discord executables and archives attachments
        // Reference: N/A
        $string4 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.iso/ nocase ascii wide
        // Description: Downloading discord executables and archives attachments
        // Reference: N/A
        $string5 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.jar/ nocase ascii wide
        // Description: Downloading discord executables and archives attachments
        // Reference: N/A
        $string6 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.msi/ nocase ascii wide
        // Description: Downloading discord executables and archives attachments
        // Reference: N/A
        $string7 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.py/ nocase ascii wide
        // Description: Downloading discord executables and archives attachments
        // Reference: N/A
        $string8 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.vbs/ nocase ascii wide
        // Description: Downloading discord executables and archives attachments
        // Reference: N/A
        $string9 = /https\:\/\/media\.discordapp\.net\/attachments\/.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}
