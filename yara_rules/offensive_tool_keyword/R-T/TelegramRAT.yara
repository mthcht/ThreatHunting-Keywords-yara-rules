rule TelegramRAT
{
    meta:
        description = "Detection patterns for the tool 'TelegramRAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TelegramRAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string1 = /\/TelegramRAT\.git/ nocase ascii wide
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string2 = /https\:\/\/t\.me\/BotFather/ nocase ascii wide
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string3 = /https\:\/\/t\.me\/machine1337/ nocase ascii wide
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string4 = /machine1337\/TelegramRAT/ nocase ascii wide
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string5 = /TelegramRAT\-main/ nocase ascii wide

    condition:
        any of them
}
