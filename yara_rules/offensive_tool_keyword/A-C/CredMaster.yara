rule CredMaster
{
    meta:
        description = "Detection patterns for the tool 'CredMaster' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CredMaster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string1 = /\scredmaster\.py/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string2 = /\scredmaster\-success\.txt/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string3 = /\scredmaster\-validusers\.txt/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string4 = /\sntlmdecoder\.py/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string5 = /\soh365userfinder\.py/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string6 = /\s\-\-plugin\sgmailenum/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string7 = /\s\-\-plugin\shttpbrute/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string8 = /\s\-\-plugin\so365enum/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string9 = /\sutils\.ntlmdecode\s/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string10 = /\/CredMaster\.git/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string11 = /\/credmaster\.py/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string12 = /\/CredMaster\-master\.zip/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string13 = /\/credmaster\-success\.txt/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string14 = /\/credmaster\-validusers\.txt/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string15 = /\/ntlmdecoder\.py/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string16 = /\/oh365userfinder\.py/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string17 = /\\credmaster\.py/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string18 = /\\CredMaster\-master\.zip/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string19 = /\\credmaster\-success\.txt/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string20 = /\\credmaster\-validusers\.txt/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string21 = /\\ntlmdecoder\.py/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string22 = /\\oh365userfinder\.py/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string23 = /05f4184029b94e304fcef2f2c6875c1fb2a226f0d94fce013643727b10b169a5/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string24 = /4665bf3f84b00ec83f005ea4feb3617acf032a69826013656a04683865c204f6/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string25 = /7bc64714fb90bddef226c04fb69f30d689384e3f0dfb89934c73ad1486e76e3a/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string26 = /acc6cd307e1dd184b722a082c177639e78421f79b0e3b26fa602f1ce8392cc4f/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string27 = /credmaster\.py\s/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string28 = /CredMaster\\passwords\.txt/ nocase ascii wide
        // Description: CredKing password spraying tool - uses FireProx APIs to rotate IP addresses
        // Reference: https://github.com/knavesec/CredMaster
        $string29 = /knavesec\/CredMaster/ nocase ascii wide

    condition:
        any of them
}
