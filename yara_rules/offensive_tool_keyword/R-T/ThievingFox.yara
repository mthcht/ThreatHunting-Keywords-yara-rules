rule ThievingFox
{
    meta:
        description = "Detection patterns for the tool 'ThievingFox' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThievingFox"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string1 = /\s\-\-mobaxterm\-poison\-hkcr/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string2 = /\s\-\-mstsc\-poison\-hkcr/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string3 = /\s\-\-rdcman\-poison\-hkcr/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string4 = /\sSuccessfully\shijacked\sKeePassXC\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string5 = /\sThievingFox\.py/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string6 = /\/logonuifox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string7 = /\/mstscfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string8 = /\/rdcmanfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string9 = /\/ThievingFox\.git/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string10 = /\/ThievingFox\.py/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string11 = /\\consentfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string12 = /\\KeePassFox\.csproj/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string13 = /\\KeePassFox\.sln/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string14 = /\\logonuifox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string15 = /\\mstscfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string16 = /\\rdcmanfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string17 = /\\ThievingFox\.py/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string18 = /28e90498456b5e0866fde4371f560e5673f75e761855b73b063eadaef39834d2/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string19 = /6A5942A4\-9086\-408E\-A9B4\-05ABC34BFD58/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string20 = /b99078f0abc00a579cf218f3ed1d1ca89fffd5c328239303bf98432732df00f0/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string21 = /Compiling\smstscax\sdll\sproxy/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string22 = /Compiling\sproxy\sargon2\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string23 = /f6f082606e6725734c4ad3fef4e9d1ae5669ebab5c9085e6ab3b409793ca2000/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string24 = /Found\sa\ssideloaded\sDLL\,\sassuming\sinjection\salready\sperformed/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string25 = /keepassxcfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string26 = /mobaxtermfox\.dll/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string27 = /Slowerzs\/ThievingFox/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string28 = /Successfully\shijacked\sKeePassXC\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string29 = /Successfully\spoisonned\sconsent\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string30 = /Successfully\spoisonned\sLogonUI\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string31 = /Successfully\spoisonned\sMobaXTerm/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string32 = /Successfully\spoisonned\smstsc\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string33 = /Successfully\spoisonned\sRDCMan\.exe/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string34 = /Sucessfully\sperformed\sAppDomainInjection\sfor\sKeePass/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string35 = /ThievingFox\.py\s/ nocase ascii wide
        // Description: collection of post-exploitation tools to gather credentials from various password managers
        // Reference: https://github.com/Slowerzs/ThievingFox
        $string36 = /uploading\smstscax\sproxy\sdll\sto\s/ nocase ascii wide

    condition:
        any of them
}
