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
        $string1 = /\sexecute\s.{0,1000}NT\sAUTHORITY\\SYSTEM.{0,1000}cmd\s\/c\s/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string2 = /\sexecute\sNT\sAUTHORITY\\SYSTEM.{0,1000}\scmd\strue\sbypass/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string3 = "/SharpToken/releases/download/" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string4 = /\]\sLeak\sof\scomplete\sPriv\stoken\ssuccessful\!/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string5 = "07249ebf1045b25fce113f88373e816cd382d2147540ec274a1b1a0356004c7b" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string6 = "30cb4b65148413d62c04a83891b7dda36fb70d4699d02a5758e9122a833b8e73" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string7 = "56d3be8ac6590cb5e593768aa36d4a0d6c39de5c96942e312876c3e0069edeae" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string8 = "59c75b410227497fbe9522a50dae6b52db1a222f946064d796ac10b918e5e4e6" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string9 = "894a784e-e04c-483c-a762-b6c03e744d0b" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string10 = "894A784E-E04C-483C-A762-B6C03E744D0B" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string11 = "8ae7a65345d809173343b02d58019e287e108d4688e483d761c89976e3ab2c9e" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string12 = "9980d0e503ffda2d4e254f2039bb6c5d7534d107178a2b4d871685ce6a899c05" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string13 = "BeichenDream/SharpToken" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string14 = "c5486044f99bdf53ddbd6d45a22c38183f094a8c0db958c189c2b601d2b2b13e" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string15 = /cmd\s\/c\swhoami.{0,1000}\sbypass/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string16 = "f45212661e27ef359bff3c919d7f6ac16517484e650bab99eecc29866f021dcf" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string17 = "f4cd930bac7a9c0ab246d0eda53e0d7b541d3cb206687e52c5f9389c53aa5098" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string18 = "fd6af36ad90f3287d849c6542f3dacd29cc06cb01bdf618a2168d0968a757894" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string19 = "SharpToken execute" nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string20 = /SharpToken.{0,1000}\sadd_user/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string21 = /SharpToken.{0,1000}\sdelete_user/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string22 = /SharpToken.{0,1000}\senableUser\s/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string23 = /SharpToken.{0,1000}\slist_token/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string24 = /SharpToken.{0,1000}\stscon\s/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string25 = /SharpToken\.csproj/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string26 = /SharpToken\.exe/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string27 = /SharpToken\.git/ nocase ascii wide
        // Description: SharpToken is a tool for exploiting Token leaks. It can find leaked Tokens from all processes in the system and use them
        // Reference: https://github.com/BeichenDream/SharpToken
        $string28 = /SharpToken\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
