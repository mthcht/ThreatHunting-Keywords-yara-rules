rule SharpToken
{
    meta:
        description = "Detection patterns for the tool 'SharpToken' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpToken"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string1 = /\sexecute\s.*NT\sAUTHORITY\\SYSTEM.*cmd\s\/c\s/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string2 = /\sexecute\sNT\sAUTHORITY\\SYSTEM.*\scmd\strue\sbypass/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string3 = /894a784e\-e04c\-483c\-a762\-b6c03e744d0b/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string4 = /BeichenDream\/SharpToken/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string5 = /cmd\s\/c\swhoami.*\sbypass/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string6 = /SharpToken.*\sadd_user/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string7 = /SharpToken.*\sdelete_user/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string8 = /SharpToken.*\senableUser\s/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string9 = /SharpToken.*\slist_token/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string10 = /SharpToken.*\stscon\s/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string11 = /SharpToken\.csproj/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string12 = /SharpToken\.exe/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string13 = /SharpToken\.git/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string14 = /SharpToken\-main\.zip/ nocase ascii wide

    condition:
        any of them
}