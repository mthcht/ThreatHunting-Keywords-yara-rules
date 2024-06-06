rule VenomousSway
{
    meta:
        description = "Detection patterns for the tool 'VenomousSway' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VenomousSway"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string1 = /\sAddTrustedDomain\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string2 = /\sAddTrustedDomain\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string3 = /\sBrtoVenomRenames\.sh/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string4 = /\sCorrupt_AMSI\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string5 = /\sCorrupt_AMSI\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string6 = /\sEnableAllMacros_AMSI\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string7 = /\sEnableAllMacros_AMSI\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string8 = /\sPatch_AMSI\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string9 = /\sPatch_AMSI\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string10 = /\sshellcode2vba\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string11 = /\sshellcode2vbafunc\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string12 = /\svenomoussway\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string13 = /\/AddTrustedDomain\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string14 = /\/AddTrustedDomain\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string15 = /\/BrtoVenomRenames\.sh/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string16 = /\/Corrupt_AMSI\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string17 = /\/Corrupt_AMSI\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string18 = /\/data\/payload\.log/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string19 = /\/EnableAllMacros_AMSI\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string20 = /\/EnableAllMacros_AMSI\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string21 = /\/Patch_AMSI\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string22 = /\/Patch_AMSI\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string23 = /\/shellcode2vba\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string24 = /\/shellcode2vbafunc\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string25 = /\/venomoussway\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string26 = /\\AddTrustedDomain\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string27 = /\\AddTrustedDomain\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string28 = /\\Corrupt_AMSI\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string29 = /\\Corrupt_AMSI\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string30 = /\\EnableAllMacros_AMSI\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string31 = /\\EnableAllMacros_AMSI\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string32 = /\\Patch_AMSI\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string33 = /\\Patch_AMSI\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string34 = /\\shellcode2vba\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string35 = /\\shellcode2vbafunc\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string36 = /\\venomoussway\.py/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string37 = /1b209500451ebe2bbe420a1ff33d946fa9e9e00399abda9ebcf9b0258fbe7902/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string38 = /1e1f0cff\-ff7a\-406d\-bd82\-e53809a5e93a/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string39 = /1ecac46b693f7ac81d6ac3198742d5b7729391f2ddc5c908f4a665c92c7dec7d/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string40 = /2d69f2dcc84e24a3b4f8c8a465f0b3b27f30ce4d24d81e96079deeec0d540f41/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string41 = /33bd8a0ee9aba1b5c63f44d993def62986b98ca01590bc1bf2638190b2dd5961/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string42 = /40a7ea977e0b28240c6b53f0b5ee130050545aa06cce4ef21afb7f82645cd0cb/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string43 = /5248816fad594b75b1f9c63e79ad931f24a346915c7ba2c50035e5c13cced4cf/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string44 = /56b15b80abb7b1bd3bb80d41347fcd9d26668499220a1dcd7d292714fbd7d350/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string45 = /57ef38c793bc416b93685ed0d2b44971860a2026a7dd9eff7dd2cd5cc6630120/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string46 = /63caa714b73110ab5d2e14db8fcddc0ddea627f5bd92bcfacb9d2c6e507e6a84/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string47 = /72efc44a791fceb9bc6e602fc079c8bf8139024dec0e580ed15f8c4fe80457bd/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string48 = /755c1d8c2e4d58422ec4da20479b10857e1e556331af09975929d13b6b5cbd53/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string49 = /766853465051ea9902106a4f90e84bf5b2bd3f4573f591b02f3882b13beafe85/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string50 = /77b5efcc93bb859a7c5667dd2e21c7cc2fb7d9bef1237875bb4dbfb1c96cc194/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string51 = /7e7c5b1923a84ddf3fcf224536dd9c917bd12ce73d5e512ee293fb6f44dc1bb4/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string52 = /8D907846\-455E\-39A7\-BD31\-BC9F81468B47/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string53 = /8D907846\-455E\-39A7\-BD31\-BC9F81468B47/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string54 = /987001995ecb92cb1fa659097e4be63c46568c00e4f91ed0162d0ed973831c50/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string55 = /9bb0c39f776edc0869cb86fd3de17fccfde02dffe82290dde30997ca10e864fb/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string56 = /ad5c08c647f8042f9d4a29581f2c740bb0634404f140cb585ad8175376adaa64/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string57 = /ae866775c318b21e13caa37dbfd2b96c03de3ba73522f437c14cc5844270c415/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string58 = /b834cbb559fcc9f0dcea0b9303b2006f14d239964b87e6f37d44d5520b93ca0d/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string59 = /b95885582cc9fc5ac5491deeb5469e36b5eacafd2699579c3a8eeb6ce1a9e0dd/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string60 = /bd4f617afbe887d10f2e971d98b36c62e0d0bb14a8020c16e308f2a6543ae27c/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string61 = /be5f14ffdc5bb327e53934a9ef6c55500e8d4ffd920a77df0b6ae209793567a5/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string62 = /BinaryToVbaFunc\(/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string63 = /ccf676c0d9c215b6de3a3219688e3f5e20a7a21191ef6a25b382c2c0ec19a7e2/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string64 = /cd618bc8eaec4bf2397840938f63f50ddea5458918186a249af976bd081e166e/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string65 = /D0CBA7AF\-93F5\-378A\-BB11\-2A5D9AA9C4D7/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string66 = /D0CBA7AF\-93F5\-378A\-BB11\-2A5D9AA9C4D7/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string67 = /d4254babd731bc584ca2e41f98f2f570b43ba92dcfbb0e0bee1cab109a5b096c/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string68 = /DEBUG\-preobfuscation\.vba/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string69 = /DUAR_Survey_v3\-cleanedx64\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string70 = /DUAR_Survey_v3\-cleanedx86\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string71 = /DUAR_Survey_v4\-cleanedx64\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string72 = /DUAR_Survey_v4\-cleanedx86\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string73 = /e4ed972586dead9a986aaec11cf76e5e044549b69b2fb9bbf5a685f281997bc8/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string74 = /e532449171a8fb15657347c2b6df8391c93227af3fb386011a4e8b40d780ad24/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string75 = /FA2052FB\-9E23\-43C8\-A0EF\-43BBB710DC61/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string76 = /fc8a13a2f3a3a9d94a0b82c0a95fd6baced84cab1c0debfa7df2f3331dd3e31d/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string77 = /lib\.obfuscator\.randomizers\.vbarandomizer/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string78 = /name\sof\sthe\sgenerated\sVBA\smodule\sto\sinclude\sas\sa\spayload/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string79 = /payloads\\payloadx64\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string80 = /payloads\\payloadx86\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string81 = /ppid_shellcode_spawn\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string82 = /ppidShellcodeSpawn4\-cleaned\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string83 = /ppidShellcodeSpawn\-cleaned\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string84 = /Shellcode2VBA\(/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string85 = /Shellcode2VBAFunc\(/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string86 = /Shellcode2VBAFunc/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string87 = /stagers\/mytest_reverse_http\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string88 = /stagers\/mytest_reverse_https\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string89 = /stagers\/x64_mytest_reverse_http\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string90 = /stagers\/x64_mytest_reverse_https\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string91 = /Staging_w_padding_3\.5_x64\-cleaned\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string92 = /Staging_w_padding_3\.5_x86\-cleaned\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string93 = /Staging_w_padding_4\.X_x64\-cleaned\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string94 = /Staging_w_padding_4\.X_x86\-cleaned\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string95 = /Staging_w_padding_v3_x64\-cleaned\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string96 = /Staging_w_padding_v3_x86\-cleaned\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string97 = /Staging_w_padding_v4_x64\-cleaned\.bin/ nocase ascii wide
        // Description: VBA payload generation framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string98 = /Staging_w_padding_v4_x86\-cleaned\.bin/ nocase ascii wide

    condition:
        any of them
}
