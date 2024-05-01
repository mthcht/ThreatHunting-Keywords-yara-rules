rule LetMeowIn
{
    meta:
        description = "Detection patterns for the tool 'LetMeowIn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LetMeowIn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string1 = /\srestoresig\.py/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string2 = /\/LetMeowIn\.git/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string3 = /\/restoresig\.py/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string4 = /\\restoresig\.py/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string5 = /0x4d\,\s0x44\,\s0x4d\,\s0x50\,\s0x93\,\s0xa7\,\s0x00\,\s0x00/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string6 = /736b362973af7010de9bf1cea58547a17a236e81a2084c344cf06a1b184698bb/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string7 = /C\:\\\\temp\\\\debug\.dmp/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string8 = /Creating\soffline\scopies\sof\sthe\sLSASS\sprocess\sto\sperform\smemory\sdumps\son/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string9 = /da5d6eca1efe3219fa8102a0afbf9823dc8b2c00dd53af20960ed29bca1b2cef/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string10 = /Don\'t\sbe\sevil\swith\sthis\.\sI\screated\sthis\stool\sto\slearn/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string11 = /\'l\'\,\s\'s\'\,\s\'a\'\,\s\'s\'\,\s\'s\'\,\s\'\.\'\,\s\'e\'\,\s\'x\'\,\s\'e\'/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string12 = /L\'D\'\,\sL\'b\'\,\sL\'g\'\,\sL\'h\'\,\sL\'e\'\,\sL\'l\'\,\sL\'p\'\,\sL\'\.\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\\0\'/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string13 = /LetMeowIn\.exe/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string14 = /LetMeowIn\-main\.zip/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string15 = /L\'n\'\,\sL\'t\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\.\'\,\sL\'d\'\,\sL\'l\'\,\sL\'l\'\,\sL\'\\0\'/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string16 = /L\'S\'\,\sL\'e\'\,\sL\'D\'\,\sL\'e\'\,\sL\'b\'\,\sL\'u\'\,\sL\'g\'\,\sL\'P\'\,\sL\'r\'\,\sL\'i\'\,\sL\'v\'\,\sL\'i\'\,\sL\'l\'\,\sL\'e\'\,\sL\'g\'\,\sL\'e\'/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string17 = /\'M\'\,\s\'i\'\,\s\'n\'\,\s\'i\'\,\s\'D\'\,\s\'u\'\,\s\'m\'\,\s\'p\'\,\s\'W\'\,\s\'r\'\,\s\'i\'\,\s\'t\'\,\s\'e\'\,\s\'D\'\,\s\'u\'\,\s\'m\'\,\s\'p\'/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string18 = /Meowmycks\/LetMeowIn/ nocase ascii wide
        // Description: A sophisticated covert Windows-based credential dumper using C++ and MASM x64.
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string19 = /Try\sopening\sit\swith\sMimikatz\snow\s\:\)/ nocase ascii wide

    condition:
        any of them
}
