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
        $string1 = /.{0,1000}\sexecute\s.{0,1000}NT\sAUTHORITY\\SYSTEM.{0,1000}cmd\s\/c\s.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string2 = /.{0,1000}\sexecute\sNT\sAUTHORITY\\SYSTEM.{0,1000}\scmd\strue\sbypass.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string3 = /.{0,1000}894a784e\-e04c\-483c\-a762\-b6c03e744d0b.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string4 = /.{0,1000}BeichenDream\/SharpToken.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string5 = /.{0,1000}cmd\s\/c\swhoami.{0,1000}\sbypass.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string6 = /.{0,1000}SharpToken.{0,1000}\sadd_user.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string7 = /.{0,1000}SharpToken.{0,1000}\sdelete_user.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string8 = /.{0,1000}SharpToken.{0,1000}\senableUser\s.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string9 = /.{0,1000}SharpToken.{0,1000}\slist_token.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string10 = /.{0,1000}SharpToken.{0,1000}\stscon\s.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string11 = /.{0,1000}SharpToken\.csproj.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string12 = /.{0,1000}SharpToken\.exe.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string13 = /.{0,1000}SharpToken\.git.{0,1000}/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string14 = /.{0,1000}SharpToken\-main\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
