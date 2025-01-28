rule BypassAddUser
{
    meta:
        description = "Detection patterns for the tool 'BypassAddUser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BypassAddUser"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string1 = /\/BypassAddUser\.exe/ nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string2 = /\/BypassAddUser\.git/ nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string3 = "/BypassAddUser/releases/download/" nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string4 = "/BypassAddUser/tarball/" nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string5 = "/BypassAddUser/zipball/" nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string6 = /\\BypassAddUser\.exe/ nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string7 = /\\BypassAddUser\-master/ nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string8 = "2e10ff03c18dcdeda7ccb185154f17ae29f54920a489edd270c535d7813366e0" nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string9 = "446dded3a070a586ff2c25e9a17784ed650e594e9a08b703c4cbd2662b95c94c" nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string10 = "559b3c946bba5edb17f646da5b0b4e259ad3af12aafea6744b1502230419cd6b" nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string11 = "5f76ace41e6efb7af838f936421f53fd66eed1efdcfde03950f3432816fadeed" nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string12 = "7FDCF4E0-2E6A-43D5-80FB-0A1A40AB3D93" nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string13 = /BypassAddUser\.exe\s\-/ nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string14 = "d8512753450da47e16944a61c468294e7a2617f244bbe6595fedf0249af0bba3" nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string15 = "e64efe84d00a0c06cc9672f7d2c96e39c6ef7ef4b8ff1671f35e369a03431af9" nocase ascii wide
        // Description: Bypass antivirus software to add users
        // Reference: https://github.com/TryA9ain/BypassAddUser
        $string16 = "TryA9ain/BypassAddUser" nocase ascii wide

    condition:
        any of them
}
