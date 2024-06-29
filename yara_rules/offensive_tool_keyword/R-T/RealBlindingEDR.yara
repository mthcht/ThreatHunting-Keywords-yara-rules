rule RealBlindingEDR
{
    meta:
        description = "Detection patterns for the tool 'RealBlindingEDR' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RealBlindingEDR"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string1 = /\.exe\sc\:\\.{0,1000}\.sys\s3\sclear/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string2 = /\/RealBlindingEDR\.git/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string3 = /\/RealBlindingEDR\/tarball/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string4 = /\/RealBlindingEDR\/zipball/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string5 = /\\RealBlindingEDR\.vcxproj/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string6 = /\\RealBlindingEDR\\/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string7 = /082f932faefd33a4e3500c5cb8e119e09d5f914de6d18f16162b48bba15bb7d4/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string8 = /09efed04888379b1fa6378ec5c4a944626129d92793a132ff56ab5d11fe53714/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string9 = /11360c9e4f50a098a4abfc0d6c6d19b8fa73ca872c462dc4e9b3d6a24a5abb22/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string10 = /209948811ece8dd5cff6fab03402232677c2625fad1272ddc964ed7869b46eeb/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string11 = /283b1a457e8aff360521928e64447e360752cc978287e51f67934fc803699c11/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string12 = /2c2e4a89c50f2f7fdb136b2435074b271f0574b0fa4629aacb6cffbc05d5940b/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string13 = /349728a1f521a0584cd5da88fd781c2927a6b2b6da356d79279b695c0af987b6/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string14 = /6a48338880ea3ada4e5675edda95cfa57976ee18b6de9fbf6ab5ce545ee42ea8/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string15 = /6f430900ee17bc63c79e6c42bfff16829205948b1e136bd4bc6d02301ba09d76/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string16 = /75f525cfddff5015fe3aada97fd9ed1b51657297f1f5fa494c3b73ad7766105a/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string17 = /7eafe227a92bd29f811ecf7457d7170ffe65962b5048a8b431c68bc1121fac21/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string18 = /7f8e123e9191b4e2299eb159da8776f51430445847529ff1f01b469acb04be2b/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string19 = /81fc4f198955aef68c590f3c04dc1fd4184a7e7b55648a67422a51f3dcf79382/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string20 = /A62776D0\-CF96\-4067\-B4BE\-B337AB6DFF02/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string21 = /aa8b4f53e6ca8db9d8b13db3b0a250724b9ef472d99bb5c1ad0da8e10f7c95c7/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string22 = /aac934f5656f3d2f861a4e0ccaa83175bb2fa9f5b8d893192ec287f2097bf18a/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string23 = /ac62eec9b4b7616cd207fda9ff22de6905f3872dcc81d03e5d67fe87e4e3b448/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string24 = /acac4db9c3f6c44711409a3fb564de89a747643d53b8d65c9c3a06e56f28875f/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string25 = /b697318c942f44d36de647d4054759b7297ff90aba4de22d41488698b9d3e32c/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string26 = /bXl6LnhjZ0BnbWFpbC5jb20\=/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string27 = /c\:\\\\echo_driver\.sys/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string28 = /CreateFile\(L\"\\\\\\\\\.\\\\EchoDrv/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string29 = /dad3df98ecb98bce9aee81b110ce6fca2ebba82fd56df1507b0a97688eb8d9bc/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string30 = /f4029b49066c2eaacff2b8ff2cc6b0c2869720666d21432eb080c489a261678c/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string31 = /myz\.xcg\@gmail\.com/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string32 = /myzxcg\/RealBlindingEDR/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string33 = /RealBlindingEDR\.cpp/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string34 = /RealBlindingEDR\.exe/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string35 = /RealBlindingEDR\.h/ nocase ascii wide
        // Description: AV/EDR evasion
        // Reference: https://github.com/myzxcg/RealBlindingEDR
        $string36 = /RealBlindingEDR\/releases/ nocase ascii wide

    condition:
        any of them
}
