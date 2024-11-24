rule WinPwnage
{
    meta:
        description = "Detection patterns for the tool 'WinPwnage' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinPwnage"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string1 = /\swinpwnage\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string2 = /\/elevate_handle_inheritance\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string3 = /\/elevate_mofcomp\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string4 = /\/elevate_named_pipe_impersonation\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string5 = /\/elevate_schtasks\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string6 = /\/elevate_token_impersonation\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string7 = /\/elevate_wmic\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string8 = /\/exec_diskshadow\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string9 = /\/exec_ftp\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string10 = /\/exec_pcalua\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string11 = /\/exec_shdocvw\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string12 = /\/persist_bitsadmin\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string13 = /\/persist_cortana\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string14 = /\/persist_dll_explorer\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string15 = /\/persist_hkcu_run\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string16 = /\/persist_hklm_run\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string17 = /\/persist_ifeo\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string18 = /\/persist_mofcomp\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string19 = /\/persist_people\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string20 = /\/persist_schtask\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string21 = /\/persist_startup_files\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string22 = /\/persist_userinit\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string23 = /\/persist_wmic\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string24 = /\/uac_cmstp\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string25 = /\/uac_compmgmtlauncher\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string26 = /\/uac_computerdefaults\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string27 = /\/uac_dll_cliconfg\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string28 = /\/uac_dll_mcx2prov\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string29 = /\/uac_dll_migwiz\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string30 = /\/uac_dll_sysprep\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string31 = /\/uac_dotnet\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string32 = /\/uac_eventviewer\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string33 = /\/uac_fodhelper\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string34 = /\/uac_mockdir\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string35 = /\/uac_perfmon\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string36 = /\/uac_runas\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string37 = /\/uac_sdclt\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string38 = /\/uac_sdcltcontrol\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string39 = /\/uac_sdcltisolatedcommand\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string40 = /\/uac_silentcleanup\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string41 = /\/uac_slui\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string42 = /\/uac_token_manipulation\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string43 = /\/uac_wsreset\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string44 = /\/WinPwnage\.git/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string45 = /\/winpwnage\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string46 = /\\\\\.\\pipe\\WinPwnagePipe/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string47 = /\\elevate_handle_inheritance\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string48 = /\\elevate_mofcomp\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string49 = /\\elevate_named_pipe_impersonation\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string50 = /\\elevate_schtasks\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string51 = /\\elevate_token_impersonation\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string52 = /\\elevate_wmic\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string53 = /\\exec_diskshadow\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string54 = /\\exec_ftp\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string55 = /\\exec_pcalua\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string56 = /\\exec_shdocvw\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string57 = /\\persist_bitsadmin\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string58 = /\\persist_cortana\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string59 = /\\persist_dll_explorer\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string60 = /\\persist_hkcu_run\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string61 = /\\persist_hklm_run\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string62 = /\\persist_ifeo\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string63 = /\\persist_mofcomp\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string64 = /\\persist_people\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string65 = /\\persist_schtask\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string66 = /\\persist_startup_files\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string67 = /\\persist_userinit\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string68 = /\\persist_wmic\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string69 = /\\uac_cmstp\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string70 = /\\uac_compmgmtlauncher\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string71 = /\\uac_computerdefaults\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string72 = /\\uac_dll_cliconfg\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string73 = /\\uac_dll_mcx2prov\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string74 = /\\uac_dll_migwiz\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string75 = /\\uac_dll_sysprep\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string76 = /\\uac_dotnet\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string77 = /\\uac_eventviewer\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string78 = /\\uac_fodhelper\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string79 = /\\uac_mockdir\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string80 = /\\uac_perfmon\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string81 = /\\uac_runas\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string82 = /\\uac_sdclt\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string83 = /\\uac_sdcltcontrol\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string84 = /\\uac_sdcltisolatedcommand\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string85 = /\\uac_silentcleanup\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string86 = /\\uac_slui\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string87 = /\\uac_token_manipulation\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string88 = /\\uac_wsreset\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string89 = /\\winpwnage\.py/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string90 = ">WinPwnage<" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string91 = "0d6fe7acb2fe628db16ac731cea9e9e0d430ff5bbc5f04cfd6700b58ea54c168" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string92 = "0fcf4fd663a77b6782595c70df5f3a9910566a9820e4ca3342aeef99a6064b1a" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string93 = "1965d3bd9a3a06fe2f9706410cb44194e4b23ddb51ed23fcc3bf4ed91681c9d4" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string94 = "1c55052f6f033698ff4e88528e91070676dd2b74f259f6304a05599e902d7d63" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string95 = "1d6cb6d414c0b9502a585b5b4ec30b76823c0a91dd4d1d301af484c47e39c426" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string96 = "21c62294d438c1c391ebb39ec2540c9c3af515e656f395624ad9dbdbd214308d" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string97 = "2399482e1dd2f112f6d8fa93eb353891eb896dcaad033c343080bca99aac4544" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string98 = "242e41d85fab89e16209aaac8fe816788ec9e9bfb032a03aeaf1419c4e10c186" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string99 = "2801fabd9ad692f666d98e5850cd634681d7ffb3c71bbe9badfef2f81d35605b" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string100 = "28c7ff1a0c4d4dd8fe1d4ef309d7784e112cd98f7ff7233085fda5b00020a18a" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string101 = "2fcac3a62e1125dcdad1f7e2681de4ed2e5dc01d474f1ee5b23d156a5116d510" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string102 = "388f88340ab9e87c70b35cd3c2ea54993328d291c8606017507fa9fe3c768392" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string103 = "3b0506a5e557ba240500e7fa9017722ba54282eb8f917ea94a403854e4effc66" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string104 = "3ba3ce7c16fd05a1f6bff952c91a537157a4c901575f0d46fadb141c2c8a6842" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string105 = "42792c009e76d5dadcc9fbefde5c21157ed86b874aa8513936eefd9c1e2c3a88" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string106 = "43438e6c4a6683e369fdd9bf0d65f934e0ce0387374607269f0cb707a742d09a" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string107 = "5121c52bf1d468e8fcfffc35b724256275f7338a0fced44213e6e48fae889437" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string108 = "58c42e01802aa60be17c26ee13705be9d17a7578a7aad62b19758b2f96c5d455" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string109 = "599540abb0ae7954cd087c212457c9b3d17afad00926b27bbfa8538d3d580912" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string110 = "5f89dd30417c33eb50fb0bd4e375102ce4c0bb7932384eb7479665e7c7f3c8fe" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string111 = "60015ca2e810e1e04f6e7eb58ea019bcf0629a0f3e7ab370a7d9f7ad7bdf0420" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string112 = "603db5a0982f09dcdff3ec26a28371bc5bdd6c867e344a52e3fef572769fb5b1" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string113 = "62f733a63d38061d5768057eccce85a23d4c22748cdb5b80b9a12ffc18cc976a" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string114 = "65adc037481a4fea2f113daaa322d5970c4136a81ccc21921c3ff6fb82e3aad3" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string115 = "6a0272c76fcec8ccada97a39b4d316eb9067b1dce499d297da7d9d02ab290c0a" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string116 = "6cc6bd374582e6fe7159dcb2d665fafc657053593ffeafc2f4135cae4e5a89cd" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string117 = "6cf9eeb823773e76fa991e6092ee7da5a1310697784381e2d4f74fb9071924d1" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string118 = "6e92e67cb6ae23615bdaf6e2f238e9d99a3fbba4ab3f9118f2a53b73302c2c97" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string119 = "761284ad40b1ab849db7298733b7573b507e94c09378df84b93ce1fcb06ac6b1" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string120 = "78e8997b2a146086dbf974c2de541f845ad52ee9de76883cd6d8c76959b026f8" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string121 = "796011ef9dd06969ac3d8a663e4cbc8ceeda566dc151181445284ab44d6eb1b4" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string122 = "7cce8a658252ae3fd74663ac28d94bec3430da75a3b1c3968451dc4a82c08754" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string123 = "80777fb99fdfa860d11e9701de35fe4addb56b66d3382ee514758d367610395a" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string124 = "83aeb8fb30e7d65ffdf35d2786efc4b89957f2462a39e09a18a1194a437436c4" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string125 = "aeed8e92b0e9d7e4c9602476183d611ed9aa2db760e349eb6226dcadb2b0df80" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string126 = "b203229777ddc5db664f3d0bfba24bc7416f234139a22b2b326fa3fc49dd13cd" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string127 = "b322f5fecd5a638b4164130a96835085e46d3f682f05ad402261419bea71f79b" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string128 = "b39fc6b0494a3543d3a96e7521f902268b447625aecacff3b241a8ce0b6419f8" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string129 = "b50db46d79c02f7ceca2ee8dfd3a9767b897089a3777632c061e1f79662892b1" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string130 = "b614be4e8653504d49488b1e14688f82bb6e96112c0780d24ce145f18751893e" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string131 = "b700d5540e96d53325b1d2616925e34694ab52a4b144a0e250263895f8bad882" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string132 = "bba6a9e8cad0cb6d31618c1cc565475cc23487f624a202002bba3170905ce614" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string133 = "bc160ae1d1dbef0c815e3ed63f873b3e753e4d5e950af24c76b08fef5be4c7b4" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string134 = "bc791951b9137e1d891721b95f21d5414e1d792813b976547d3f58a745023797" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string135 = /Bypass\sUAC\susing\s\.NET\s/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string136 = "Bypass UAC using cliconfg " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string137 = "Bypass UAC using cmstp " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string138 = "Bypass UAC using compmgmtlauncher " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string139 = "Bypass UAC using computerdefaults " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string140 = "Bypass UAC using eventviewer " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string141 = "Bypass UAC using fodhelper " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string142 = "Bypass UAC using mcx2prov " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string143 = "Bypass UAC using migwiz " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string144 = "Bypass UAC using mock " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string145 = "Bypass UAC using perfmon " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string146 = "Bypass UAC using runas, " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string147 = "Bypass UAC using sdclt " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string148 = "Bypass UAC using silentcleanup " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string149 = "Bypass UAC using slui " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string150 = "Bypass UAC using sysprep " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string151 = "Bypass UAC using token " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string152 = "Bypass UAC using wsreset " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string153 = "c254090da39e70c2a20291aee65043f470acc77d7e6dede2ccc4784d75c024c4" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string154 = "cclauss/WinPwnage" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string155 = "d240dc4fa0146d782dc43ff14fc47afb81080057a2843cd2ba679a7e6b2197aa" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string156 = "d860326bffbb645fcd78d65712b1950af17e47fdeab96e6dfa0a061a0723e570" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string157 = "DEFCON-25-Workshop-Ruben-Boobeb-UAC-0day" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string158 = "e39e2ee96b9f8bd34337c60dc9b8749f526a236664fefcf704180e818221daaa" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string159 = "e56e4f05ebf54dc82142046543f2c81ffeb50eb6b342387461106fc27358fda0" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string160 = "echo 'WinPwnage' " nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string161 = "eda3dc681554b274b5cdf9cdc4d1d2248a45ed61a3f309210d1a79bab4e53113" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string162 = "f18594dd9281bf3b8450f6528e209afca27b24998d653077f1e371126ea0aeea" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string163 = "f54687027a34fa171337c495bbf41f5d099f580d38fb2404136b7ddd19be8dde" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string164 = "f66f7bfa92e6106e77dba36fd345df2bb84a4cf9b798076e979b1b61bab53f1c" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string165 = "fa9eb14e832e32c6a7bc4c1a2a4aa2db3c94a43316ac8d702a983db4bf2b4c68" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string166 = "fb84be2d35811783dc2a2f6d1b1a80e4173c2f204f60a595f110134e3df5fee4" nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string167 = /from\swinpwnage\./ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string168 = /winpwnage\.functions\.execute\.exe/ nocase ascii wide
        // Description: various exploitation tools for windows 
        // Reference: https://github.com/rootm0s/WinPwnage
        $string169 = "WinPwnageVPN" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
