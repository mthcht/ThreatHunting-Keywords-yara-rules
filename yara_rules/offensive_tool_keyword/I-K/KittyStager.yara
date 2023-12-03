rule KittyStager
{
    meta:
        description = "Detection patterns for the tool 'KittyStager' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KittyStager"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string1 = /.{0,1000}\sKittyStager.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string2 = /.{0,1000}\/edr\-checker\/.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string3 = /.{0,1000}\/getLegit\/cdnl.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string4 = /.{0,1000}\/getLegit\/grkg.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string5 = /.{0,1000}\/getLegit\/prvw.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string6 = /.{0,1000}\/getLegit\/qhwl.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string7 = /.{0,1000}\/getLegit\/tsom.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string8 = /.{0,1000}\/getLegit\/zijz.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string9 = /.{0,1000}\/kittens\/haloKitten.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string10 = /.{0,1000}\/kittens\/recycleKitten.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string11 = /.{0,1000}\/KittyStager\/.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string12 = /.{0,1000}\/postLegit\/grkg.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string13 = /.{0,1000}\/postLegit\/qhwl.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string14 = /.{0,1000}\/shellcode.{0,1000}loader\.bin.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string15 = /.{0,1000}\\basicKitten\.exe.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string16 = /.{0,1000}\\kitten\.exe.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string17 = /.{0,1000}\\KittyStager.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string18 = /.{0,1000}127\.0\.0\.1:1337.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string19 = /.{0,1000}505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string20 = /.{0,1000}bananaKitten\.exe.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string21 = /.{0,1000}dllKitten\.dll.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string22 = /.{0,1000}Enelg52\/KittyStager.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string23 = /.{0,1000}http:\/\/127\.0\.0\.1:8080.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string24 = /.{0,1000}http:\/\/localhost:8080.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string25 = /.{0,1000}Invoke\-EDRChecker\.ps1.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string26 = /.{0,1000}kitten\.dll.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string27 = /.{0,1000}kitten\/basicKitten.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string28 = /.{0,1000}kitten_test\.go.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string29 = /.{0,1000}kittens\/bananaKitten.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string30 = /.{0,1000}KittyStager\s\-.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string31 = /.{0,1000}KittyStager\s\?.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string32 = /.{0,1000}KittyStager\s\?\?.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string33 = /.{0,1000}KittyStager\.git.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string34 = /.{0,1000}KittyStager\/cmd.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string35 = /.{0,1000}KittyStager\/internal.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string36 = /.{0,1000}KittyStager\/kitten.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string37 = /.{0,1000}localhost:1337.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string38 = /.{0,1000}malware\.NewConfig.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string39 = /.{0,1000}\-o\s\skitten\.exe.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string40 = /.{0,1000}output.{0,1000}kitten\.exe.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string41 = /.{0,1000}shellcode.{0,1000}shellcode\.bin.{0,1000}/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string42 = /.{0,1000}xzfbmR6MskR8J6Zr58RrhMc325kejLJE.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
