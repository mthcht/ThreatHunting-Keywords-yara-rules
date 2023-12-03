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
        $string1 = /.{0,1000}\/TelegramRAT\.git.{0,1000}/ nocase ascii wide
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string2 = /.{0,1000}https:\/\/t\.me\/BotFather.{0,1000}/ nocase ascii wide
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string3 = /.{0,1000}https:\/\/t\.me\/machine1337.{0,1000}/ nocase ascii wide
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string4 = /.{0,1000}machine1337\/TelegramRAT.{0,1000}/ nocase ascii wide
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string5 = /.{0,1000}TelegramRAT\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
