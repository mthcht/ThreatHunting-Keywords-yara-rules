rule TelegramRAT
{
    meta:
        description = "Detection patterns for the tool 'TelegramRAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TelegramRAT"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string1 = /https\:\/\/api\.telegram\.org\/bot.{0,1000}\/sendMessage/ nocase ascii wide

    condition:
        any of them
}
