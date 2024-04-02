rule fscan
{
    meta:
        description = "Detection patterns for the tool 'fscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fscan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string1 = /\sfscan\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string2 = /\sfscan32\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string3 = /\sfscan64\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string4 = /\sfscanarm64\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string5 = /\sfscanarmv6\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string6 = /\sfscanarmv7\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string7 = /\/fscan\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string8 = /\/fscan\.git/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string9 = /\/fscan\/releases\/download\// nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string10 = /\/fscan_freebsd_arm64/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string11 = /\/fscan_mac_arm64/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string12 = /\/fscan32\s/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string13 = /\/fscan32\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string14 = /\/fscan386\s/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string15 = /\/fscan64\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string16 = /\/fscanamd64\s/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string17 = /\/fscanarm64\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string18 = /\/fscanarmv6\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string19 = /\/fscanarmv7\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string20 = /\[\+\]\sPocScan\s/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string21 = /\[\+\]\sWmiExec\s/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string22 = /\\fscan\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string23 = /\\fscan\\common\\proxy/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string24 = /\\fscan\\WebScan\\pocs\\/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string25 = /\\fscan32\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string26 = /\\fscan64\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string27 = /\\fscanarm64\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string28 = /\\fscanarmv6\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string29 = /\\fscanarmv7\.exe/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string30 = /027bf95a524ee9daf472869e548c9221b16d4a5230de187e5ae9ba9a9e98cfba/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string31 = /06e7d0050e4aac352307c5b20372badd841e275bafc1dfe2ecbd0f2ad6366f81/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string32 = /0b3924b330e85ff7db62e4d7e665397fd04c3b056b135a184aa87fcabbf1fad9/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string33 = /0b8e4ffbabf5f6e7167013a324e67e2a359d35043145eb8af7d8815e7e12242b/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string34 = /16bef09e16119f1754a6b4283e93ff7a17cfdd7c043c3ff05a3d41f128ead52e/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string35 = /1a524806875110320dacb05bb8a00bbe07f8618ff23a82effad887df9952f459/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string36 = /25125be2945ae98284abb64b279fe13021d1d02895b85a4e02a4fcd6ec8415cc/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string37 = /3b66b9ef669a7aca55f87ccce04ab1849d23d18c522b5f2514ca0637398ca250/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string38 = /3f63c1d262a6e900833b2dbd615f72006785c124d4ca7fda01cd621ca615865f/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string39 = /405e9c6f0b2ea355c45a80236dd541ecee957c73194dc3e7948b3ae02c8c70ea/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string40 = /5cd6f1ac11ce75c742358c9225983712e9ae31fd16e052b377a795d8ba4d18f6/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string41 = /62ba281147ceeefca5bd15f58ac52125bc42b0e134a6fcb4bd90efdae0fce318/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string42 = /633bd0cfd64ccc0030ca38148459f71dba02cf3ce103ce24d8a0872c00a26eeb/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string43 = /675f1d8076801a64dc3c39916e52ac7b345b7d1c9454a01f270ca9796dd86f7e/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string44 = /69e041111e26111f406a95d9b91b5004f60ba367a0c90ffe34146e064513e56b/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string45 = /6facdc6a09f2d89e156a7b11dc628815f4a00ba25ce37f9443f4fb7f50877f85/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string46 = /723c4fa580d252cfdafda962e5abb6b45eec8c9aae56497d98983ce6dcf9a1ac/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string47 = /78eed41cec221edd4ffed223f2fd2271a96224fd1173ed685c8c0b274fe93029/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string48 = /7beae9c75c8e6e87a776f82461256a983e0fcd2ab169ea2293efa08f486ed33b/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string49 = /7e6b9406c2a12c93a7c56e4e2c79dd4eb1e562c772aef13ebd006abb727a2854/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string50 = /84dbd3a0c2e858b59822ee50b7d72972851ca692416c15c5f351831381aa4db9/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string51 = /929dbe39814a7b4acba0efe0a552840aeb1e9a5b1f8045be633e6fb68f4e2155/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string52 = /9b140ac9343598961b3d5699eedc389d78c7c88271453fa37c7e3d2853364234/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string53 = /9f9675403c2be03232b1c3abe344bf0f4188454955ba89592be52ef77add4a39/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string54 = /9fc3fe230f30e5b9f9bb15065bf62269f494f51f744857d6b8ac90a9937f5bc0/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string55 = /a25c5e7baec3573c2a78872808c709d702714f3a11e57d06b62244c3eca2a834/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string56 = /aa12c40bc0ef87b1b706f1e9062d72d8c67c3b4b3347741efb38cf71817777d2/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string57 = /b19a46f99b649dc731ed5c8410bda7e0385d15e1b9aab1e467b05dccd7753865/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string58 = /b26458a0b60f4af597433fb7eff7b949ca96e59330f4e4bb85005e8bbcfa4f59/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string59 = /b4a1ab9bd2528e57f4a018ac84934c6bdcd67aaaf269f76c15fa739432409f3b/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string60 = /b9919cdb3ebf7abed7458e357a71924bb0dd43332e90c30a6f146caefcf56baa/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string61 = /bc422a4e1b6a351ac6fe73d496015cfa6a9dbd5e38566c6f44a59faff83ee95a/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string62 = /c7985c82769ce2d6d68e3ed3926df1bc47523990c56cfa1ebe3e511e4b96a903/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string63 = /c86b6630f868d20303e940cd8f1a8805f1013bc567938a79cedb318b07f5f498/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string64 = /d61ec93dd0760f68a6b98f8dd073fcbbe7edeb55cbd3281f12df0af42ce6f794/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string65 = /d9940f5a09a04a949545eedb6818ce0ce001cc7596a63959e0940d31b6dc4834/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string66 = /d9d5daaecd31c7616b01456da34cb3b51006b5a7697af4cadfa8167e7a8b6f81/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string67 = /dc5d95d4ce6cee631b546e1bbfa9f090f66e4167edd5dd828f567c7fc30978dc/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string68 = /e2940f2785f9f9b38e5cac80100a401145f558602a7af45475760884aeba44f9/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string69 = /ebaa36db295f1c3a7d59e460ce6813221d0097f3c12ce26e818d4d4ac83c0919/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string70 = /f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071a0b1/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string71 = /f4ea99dc41cb7922d01955eef9303ec3a24b88c3318138855346de1e830ed09e/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string72 = /f6bb09ea48d85445fb1295a7b93ead6700a17c8f839624871f4faf024e18e39f/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string73 = /fscan\.exe\s\-/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string74 = /Running\sfinal\sexploit\spacket/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string75 = /shadow1ng\/fscan/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string76 = /User\-Agent\:\s.{0,1000}echo\;\secho\;\s\/bin\/bash\s\-c\s/ nocase ascii wide

    condition:
        any of them
}
