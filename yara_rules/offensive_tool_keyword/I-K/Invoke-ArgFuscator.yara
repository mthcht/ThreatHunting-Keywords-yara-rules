rule Invoke_ArgFuscator
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ArgFuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ArgFuscator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string1 = /\/ArgFuscator\.zip/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string2 = /\/Invoke\-ArgFuscator\.git/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string3 = "/Invoke-ArgFuscator/releases/" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string4 = "/Invoke-ArgFuscator/tarball/" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string5 = "/Invoke-ArgFuscator/zipball/" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string6 = /\\ArgFuscator\.zip/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string7 = /\\Invoke\-ArgFuscator\-main/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string8 = "03269801085da5702202a4d2cd0f006bf93e63b6da69c588414380cdf3753349" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string9 = "0e2a30af2c626fd1f134d32daf8d615bfae7568fd43484e5f5fc489ceb0b2faf" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string10 = "1de467a837f7bf75b522bf34b0a2711213d73c7ca8101b4535a5bbdc94323ac7" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string11 = "2308bdcf6b10c8d36213bbb8afba67549558c4cd9b112493b9e9d4b7e2d365ca" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string12 = "2f8ed85860e64bd52c6ef3b7a4e405a9934ca78139751adb118a0074ae7ced2d" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string13 = "3c6843232a8479a389876f73cf69d7277ae2c7e635918699e183c062799dbd16" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string14 = "3e451b530ade34ae48f51aebf8db1609272ea8d1b1438cfa7c3d570e91b39bd9" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string15 = "457026969789119712188521674e7eb3a1cb4ab5e121b6ba80515090eea71d27" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string16 = "4d14760b49f084714c356b922b2889402fca1faa5145f64c4441746897fe4d7b" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string17 = "5d718f2a4cb244409b90df00bca8dd43b57e5892743f203f0f382eb863b1d8f4" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string18 = "65dd5aa4e6cc05a7bd84be96d769806dfbe19c8c0451c13445100597fe4698d0" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string19 = "6c4c9900e2d006a9b7dde59982905c5c6354eb8de5ceae88f1da96161756042d" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string20 = "7b519e14d5860852dd54139ef9bff6a52a5e400afc6cbd1b6d7bc2a75ed674e6" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string21 = "835544862f1683ef3996a1b9653a0daf1937d2cdd973004e4fa5003fef54a893" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string22 = "844d9edc-57ad-4fcc-9fd5-77a69d4bf569" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string23 = "94bd506457e76c837592396e349c0d2da7f783ed0d1e3f083457b4ac013286cb" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string24 = "a7cc4efa0b13e199acd6d09b696b7d2ff0cff7aefd420ef9e87a216a396b1e9d" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string25 = "a9843a81603f299fb87f371052b47798338252b58ad8ef56dfee4bf462322eb6" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string26 = /ArgFuscator\.net\/archive\/refs\/heads\// nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string27 = /ArgFuscator\.net\-main/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string28 = "b72782bc3e57e54fe21104feeb218779cf739eafafab30b70a0d75f89083cdcd" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string29 = "d21cf671b3547b844a9adbe858c032e02f68b5d475de06b92e7776cd79d9db27" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string30 = "Install-Module -Name Invoke-ArgFuscator" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string31 = "Invoke-ArgFuscator -" nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string32 = /Invoke\-ArgFuscator\.ps1/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string33 = /Invoke\-ArgFuscator\.psd1/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string34 = /Invoke\-ArgFuscator\.psm1/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string35 = /Invoke\-ArgFuscator\-main\.zip/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string36 = /Modifiers\\CharacterInsertion\.psm1/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string37 = /using\smodule\s\\"Modifiers\\FilePathTransformer\.psm1\\"/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string38 = /using\smodule\s\\"Modifiers\\OptionCharSubstitution\.psm1\\"/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string39 = /using\smodule\s\\"Modifiers\\QuoteInsertion\.psm1\\"/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string40 = /using\smodule\s\\"Modifiers\\RandomCase\.psm1\\"/ nocase ascii wide
        // Description: generate obfuscated command-lines for common system-native executables
        // Reference: https://github.com/wietze/Invoke-ArgFuscator
        $string41 = "wietze/Invoke-ArgFuscator" nocase ascii wide

    condition:
        any of them
}
