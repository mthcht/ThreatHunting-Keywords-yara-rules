rule specula
{
    meta:
        description = "Detection patterns for the tool 'specula' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "specula"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string1 = /\/capture_netntlmv2\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string2 = /\/demo\.specula\.com\// nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string3 = /\/Getallregvalues\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string4 = /\/helperFunctions\/Delregkey_hkcu\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string5 = /\/helperFunctions\/Delregvalue_hkcu\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string6 = /\/helperFunctions\/dir_creator\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string7 = /\/helperFunctions\/dir_lister\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string8 = /\/helperFunctions\/Getallregkeys\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string9 = /\/helperFunctions\/Getallregvalues\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string10 = /\/helperFunctions\/Getregvalue\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string11 = /\/helperFunctions\/Setregvalue_hkcu\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string12 = /\/specagents\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string13 = /\/specmodule\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string14 = /\/specpayload\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string15 = /\/spectaskbook\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string16 = /\/specula\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string17 = /\/specula_log\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string18 = /\/specula\-main\.zip/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string19 = /\[\+\]\sGenerating\s\.reg\spayload/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string20 = /\\capture_netntlmv2\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string21 = /\\capture_netntlmv2\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string22 = /\\delkeyhkcuregistry\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string23 = /\\delkeyhkcuregistry\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string24 = /\\Delregkey_hkcu\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string25 = /\\Delregvalue_hkcu\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string26 = /\\delvaluehkcuregistry\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string27 = /\\delvaluehkcuregistry\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string28 = /\\download_filehttp\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string29 = /\\download_filehttp\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string30 = /\\enum_installed_software\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string31 = /\\execute_excel4macro\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string32 = /\\execute_excel4macro\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string33 = /\\execute_registerxll\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string34 = /\\execute_registerxll\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string35 = /\\getallkeysregistry\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string36 = /\\getallkeysregistry\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string37 = /\\Getallregkeys\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string38 = /\\Getallregvalues\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string39 = /\\getallvaluesregistry\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string40 = /\\getallvaluesregistry\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string41 = /\\getvalueregistry\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string42 = /\\getvalueregistry\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string43 = /\\list_addcomputertodomain\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string44 = /\\list_amsiproviders\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string45 = /\\list_amsiproviders\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string46 = /\\list_applocker\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string47 = /\\list_applocker\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string48 = /\\list_asreproast\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string49 = /\\list_asreproast\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string50 = /\\list_autoruns\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string51 = /\\list_autoruns\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string52 = /\\list_clipboard\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string53 = /\\list_clipboard\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string54 = /\\list_domaininfo\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string55 = /\\list_lapspassword\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string56 = /\\list_lapspassword\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string57 = /\\list_localadmins\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string58 = /\\list_localadmins\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string59 = /\\list_localusers\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string60 = /\\list_localusers\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string61 = /\\list_passwordnotrequired\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string62 = /\\list_passwordnotrequired\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string63 = /\\list_passwordpolicy\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string64 = /\\list_passwordpolicy\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string65 = /\\list_recentcommands\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string66 = /\\list_recentcommands\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string67 = /\\list_recyclebin\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string68 = /\\list_recyclebin\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string69 = /\\list_scheduledtasks\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string70 = /\\list_scheduledtasks\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string71 = /\\list_whoami\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string72 = /\\list_whoami\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string73 = /\\remove_allowlongscriptruntime\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string74 = /\\remove_allowlongscriptruntime\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string75 = /\\set_allowlongscriptruntime\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string76 = /\\set_allowlongscriptruntime\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string77 = /\\setvaluehkcuregistry\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string78 = /\\setvaluehkcuregistry\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string79 = /\\specagents\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string80 = /\\specmodule\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string81 = /\\specpayload\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string82 = /\\specpromptpayload\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string83 = /\\specula\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string84 = /\\specula_com\.dll/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string85 = /\\specula_log\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string86 = /\\SpeculaApi\.cpp/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string87 = /\\SpeculaApi\.dll/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string88 = /\\SpeculaApi\.Specula/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string89 = /\\SpeculaApi\.x64\.dll/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string90 = /\\stop_outlook\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string91 = /\\stop_outlook\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string92 = /\\wmi_killprocname\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string93 = /\\wmi_killprocname\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string94 = /\\wmi_killprocpid\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string95 = /\\wmi_killprocpid\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string96 = /\\wscriptshell\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string97 = /\\wscriptshell\.txt/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string98 = /0075f7d5a315c6bf6d8bbe89a2481e673a8a61e79afbe89afd33e11634fd1caa/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string99 = /01c856cd200bc91b6c8c6e7e11de385b34da4fb2789a497279910238e8dbe70a/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string100 = /08809731dc3d878c71e0c6bfc5d27a78912aa67483533570da7bc475d22bd0ab/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string101 = /09086d1efecc096e7418987b2a4733595afd2bdcf1d1073a53bc7f4eba4e8833/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string102 = /0b7662a80318e6fe243f57a7a1acd74d310f25a4876dc9a1ddaad9cb164b8ac3/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string103 = /0cb637ff999fdec518a1792b5d98d6ffbd9eb65ebb828950bf9fd488d351e190/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string104 = /0d6ab504d6e011e57dad5e5173dcfe3d7e1234ad3edaf880437071eaad3c2550/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string105 = /0eb04b75544e35cb6a285c97bbefa557050848d73ad9f8e7ff7a36ee7a36a68d/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string106 = /0fea5161a6fd5c671200cd69364a12d916eaf65f26263dfaa9962cd997d61f84/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string107 = /1145c0adcdf15ea7ac30cb824c417b356f15722dc2039aa6a3ffe67c2cc3bbd0/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string108 = /12a7c285045a2963e92a9440777baf1ee1c8d2b15f2df222913f04ba4f27d04b/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string109 = /1366b4cf8885fa1960344f67c82202ec3227b78a67c14c64ba981100ffe0991c/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string110 = /144ee3c2d9af200cbe10a4d0f9f78ff8fc5318ff75927e0da17b0679b002b071/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string111 = /16fef0c5d8dd0db6c928502541365471234fd1b5a8e7f8b2ea94c016d98afe5b/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string112 = /19cce61cee800661797745070ba28b0c3b7ca2b3709d883b654a9a6e01535503/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string113 = /1a57eb11c69b6af09823fc2ffe4fdaa6b70142378706af50609ba9ef92c33627/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string114 = /1b1aefd0619b7d630dbb6a1ba16a77adfc9c26b608768d119e1bdf4d3da98ec7/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string115 = /1e438cfed2d0cacdbf15d96360484541339463564d29c883afe513222df61b32/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string116 = /21d9bf55a6482b64b95791d7b90e8cc3aa1c3c133be82650daff5df113643b66/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string117 = /24b7191a8f1c5a64ef880f979ebcf6b2957278ecce023743714acddb4d9c1ebc/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string118 = /2a16d9cdb572f7860983402e56691cc4334bcc7c4f093528abe30bbcd8a2afd0/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string119 = /2bdb8c20d1daf819c4f7722597563277e1dc4ca160b29feafc269f270baa9e2f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string120 = /2d35c7451ad9957e4a3c0cdccad1e8e9ac11a1c066cf0431ecf089b51ee8a763/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string121 = /2da7517e0a483825eea29726da1398bee9b68e739151ed4febcd6ceee6b85e01/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string122 = /2f9b32300b30c7a70e5fc37adae993bd93b35d6e13b90eebb375e1718a991058/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string123 = /307925f20e73a5b32e5a5b260398f3b838f9966c1dc4e7913d3036fbb52d4508/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string124 = /356ce77ad527c67a64f6f770d67ef71a6d4ebecfd362d651cbf08c98e7f21555/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string125 = /385a076cf8b909062acbb4df72012aee93fce1cd6d1a0b3c12ee7d3f7bc2f464/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string126 = /3adf9833e9f51c6a887107d4d4b402138fbeb11c633440f9085f0a93fe1d0afa/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string127 = /3ec7beb57b5218a1fcf4586464319ef4d78ca05d00d3eb8ee13be51c8cf38cfa/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string128 = /3ee46311d18a046c6ade96546e1deac7040ac3fb2f92040d6ad1b7c32c77a6c8/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string129 = /3fabdbc17823053cc58c6cea393a110a136a3d8687d61239b6f167db573ecc08/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string130 = /426d4834e4c5f0551f0e5c9ec4778282eab7c51b54d34f7409fb95d1e538697e/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string131 = /43f6bfcdb8751cd4232241d4baf2c46333c7a71885fd9571242e16c4b4a81691/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string132 = /450bb5ca8c92ffe474f9ec1a48111c7574dd621fd326f9ff0474aabb90b3fbde/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string133 = /46f1f34d38963f9ee2e81449356b0f39475ea1f31395edfa097e08ce975b4748/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string134 = /47f24f8e55ef98aca7f72bebb5867e8935f17fc7b1d5af8d6a76934009c27635/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string135 = /48a968cb02b5e5ebbb4e3b62b2261f7b997c13f6861404968f35997b31d70643/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string136 = /4c24b427581c8989acf962bc4f42b00331b4035e2155cdf97db0298fd0a34b65/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string137 = /4ced72b74d1b71171e8af3139858e9f59455f9ce99c426b7b8ab7b436435fb45/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string138 = /4f911b0fae752353f1f78cd403a38ed44a6de2e32cfdec6b12ed5fed44a6bea1/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string139 = /50e67569fd7d2313ac7d9b446f5519a33ab4755ccb5c9829f84d8cbf4f6abc7c/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string140 = /53ceac06a248c60ecf2879fa2cab20508ddc1b73d91e8a418655c64f991838c2/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string141 = /56f8e538e4959c62f8d9d5f672a48ebea7883ec573e6df3f4dae69a5f8156eb9/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string142 = /5851121b0a7ef7c0b740d9b7912f6676317ebc41918187b3c4b7894842a0d3d4/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string143 = /59852690cccde0f1853f60abfa889899a940a43c45a4906963a52e0069b02480/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string144 = /5b52db9764212c3b11863100f5f6d34ad13af621fe9897edcea2392b39b2b70e/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string145 = /5e7519bba332d03aaca2ab30275e2afcea4b45abd4204ad3d97054775d55b830/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string146 = /5ee47f66e30d5ccc81ab8a3df639396b7e45aee360906b08012d06cdc6a13ff9/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string147 = /60049ba3c5bb513e7ab79467f76fd71f2c38a697bcca3ef1949dd31720420555/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string148 = /6169805c0a2a3eb13298f86e180539edf62ed3d6ba0fe4bfdb2735e814be347a/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string149 = /62eed3bd13a07c779ba809b4ba237a1e1e8c882f9f62bb9fcf87199213cb8824/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string150 = /63b104b8d35cf8e3ae08ed500e337ce1617533f8c0b38eef55a07cdca529324f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string151 = /64fe21c5033e01c0f5c45a9d0f990d6d4b5ae2f20416b65787385844332411/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string152 = /664ed4839518dc4ca3c904778f4deee7ea0b0ba0baabd9d2de4c4b9d9b81b77a/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string153 = /6752dd08be06b124a3e1865645b5b1a6b4f8765ac8fc3fa002bd39ec448e4ba2/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string154 = /6a27858aee472da9a5faf7649801103ea6c0cad8d2b44baec2bffc563a0f7375/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string155 = /6ac7c6229db63b7fe25b570e1b084ec373169f57479d8a3ff7ebeaaac440fafe/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string156 = /6b5477e05628d2f5c4bb2a03556dc46642e986e78d98cb4a95fa5cd49457a171/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string157 = /6b5675be7aa2c43191262f462d98730f2672d54869577e44bcbb18984544ac11/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string158 = /6c7bf018f8117a161751d7a7d3e3a6356763ba65f51db519ad72cdf8168da9e8/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string159 = /70c45d173ea7e04565166eca5d699763fc4d7c21eba93c6db67c727b0d1f23fa/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string160 = /71ad700e300bf6b1bb195321b47a176bb9fe5b20298e5d70bf0a682e1b312712/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string161 = /71da0d5262e6fdc248d1e1a9de2ea99d4ebf6f3bf629dfda1cc356e60669e64b/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string162 = /76c228ff4ca867c361bb5271c961092659ccabe899a45a46e1b0889f0a2e9ec7/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string163 = /7776b5b62b66f36a15558f7004bb319a16a2d68c11bc66b0795ee72866c08e49/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string164 = /777d2f709701210daa2b14af49128fbc4949d120f1d112b1c4d5a1453318d89f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string165 = /785103e26500da6cc70ffbd7aa5edb74b8c8a3d38741fe34bf484108e7a76f46/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string166 = /7863d0f2b0c532b9f36b62550833049f402a1267b64433b6d5c7e007252ce83f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string167 = /78e4019194c23bd123a3bdd40aad7815e0bd1db967adfea97ea3df83084d1467/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string168 = /7f049ca9ba7182193eb8c129ea0b090d498a2978fa66e36ceeab62e0be124592/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string169 = /801e85a2cc2b8d16312799bd16dc5d05985f4f2577b2d7d90ba71bd35c8ba180/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string170 = /81b24314538ad9dd740093c63a7925f039ccbdcac4e2944fd8cdf238f05ad8fc/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string171 = /828cd34ca798170da015728e4e85b2e6367ea3fac93946c0684ac643794ff3fb/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string172 = /82f1a23dfcbcf483940976e8cc71e3e3ebd71df0b37a66319973e2ed178e597b/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string173 = /84df4aaf2b050748e52b7e61ac93739d376929cb6d00e6d8cef3c6d61b71ae0f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string174 = /8559d164a6628834d0b6cf4ff457cb2d30d4960116f8c0e56e6510243f38d6f3/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string175 = /8588f8405c9048a5356cb2376ffdb20eef599763b96930818b757f4df3909841/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string176 = /86558db784a8bc92ef0e6618e81f7f75809aa39e05bb04baf00688aa8c4470da/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string177 = /868876b4a458094304af704caecdff99cac8db78f3185db609801ecbd09e3e58/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string178 = /86f965be880424c4cee7e1701532b5531da9b10db1c430f289c68b13edbb33f7/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string179 = /8b9666a09ac189375f18de24c713e0571a4bf50a9e58489d71f19378b822a623/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string180 = /8f93c473d769f7d93c9293fefb6c6f4dcca66ecbf9fba6dc968fc2d061696d0b/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string181 = /902b3361a8df50b70a7c9b88aa728fe9d5092f2dc3d8d6691da4a3bcd4a4d56e/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string182 = /90a2fd2951ffe73118f56f90197f378f17c2e79c38bb58a824f01293187fdca5/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string183 = /910a0899cdb2824c3c5d3a3872196206c17077c24f520d6661b270358b922b6f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string184 = /95bc7379dc7a1f1a8b571ae0ba24937e3d7d5423c3c917a1550dddd0e056e8a9/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string185 = /98f2b951313b8535bf4a2b0310f59426168b8e2792513d7aed4fa6f16d9fe9a3/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string186 = /9b287794f93df5f5bf9dbc8133ed9f6c84c270b87812e6b9426c1aded5eda58b/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string187 = /9e485ad4912ef50847e09de786a67ecbfddc97f0bd6b731ff15f9c03975114c9/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string188 = /9fbe53eae88ccff8713e0c14e623352af0a7424e234499e6dfa6cf7455f83ae8/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string189 = /a1eae60e964d13208a3305dcaf3d24ab8137ff67baf575200fd8d67e92c0f2ae/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string190 = /a27fce6d1589930899c893f6026891b4b7cd9e0f42322985299a3ba523a3e40f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string191 = /a40d64c15cb551bf428df95586a907b6d0efea97a05afceeac24230fd787ef0f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string192 = /a494bbc30a636c51bae886c742f6a46a9ab049c26c4143d186cbc7ee5a55099a/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string193 = /a5bd5b4800c559bdecc3cc32c76fe128e7e10f008a1224d9f6acfd06015b52a3/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string194 = /a6d05bbe01016498df38a529495f160b8fae84d8d325811e205da5300679daf4/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string195 = /a7f5996d248ea178587e34a990457b43a69ada5c4ad1e5586eca9fbcd36668df/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string196 = /a88896071aafd285ea22e4fa7ebcf5037926f0cf5674256a29d31121ddc74013/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string197 = /ae3fe47fea3540fa053326f19d7ac8198d170efea7551438d2e3deae3381f49f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string198 = /AF2D318C\-2C5A\-4C9D\-BE4C\-AA5B3E8037DB/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string199 = /b1e9925fa0a268182267f3f1d77837ed9e5ac11a342aeb8ad293b37f0ca725e5/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string200 = /b2f54ca92d09074aaebf19ee7e0c6078075a43c269a4cc045e508d041c2b1e50/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string201 = /b49ec9495cebbc03139dd1e0a5ccc665760e1cc0770fd896077db21abc122b2b/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string202 = /b4c1fe4b72f4cfe5ee58e4196e4620eea2a70641a033c25d0cb96758ec672d7f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string203 = /B58767EE\-5185\-4E99\-818F\-6285332400E6/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string204 = /b701f7ca92ab2180873b070d6a3354819c642c077ba7d9ab96eb20e876b9297d/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string205 = /b710e7fbb1b4fbe07cc648c967c94a516308cfb0914f16ac5357f8caedc9f375/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string206 = /b8480a3711130c5b2b71a873611a66a48edcadadbdb3309577d7aa943fa2a1e6/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string207 = /b85ba959ef3133cc86ae808e0e8f58af054f00cc96b34ef6973f3942ee80d056/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string208 = /b87c2a25945a735f4550eba7155c5e363e0406b7930b7205c762540ac672a097/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string209 = /bb89de818ececdcc29e0dae02fc30b07b8646c45a2fd46fa0bb55659b946aa93/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string210 = /bda653b24a1896f5444b4337eaa07ee541739219ec949d30357d2cce16a99b0c/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string211 = /bec1bf8b5dc63cdda1a346684b1ebdae02cb2f34d18ef589debc018d6bc04253/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string212 = /c\:\\\\com\-test\\\\v2\\\\/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string213 = /c\:\\com\-test\\v2\\/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string214 = /c016717b991de5e956b84818eac0822ae860329a546c07f8ae4443d189f97522/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string215 = /c19100c9fbebb503b21a36ca64471807cf3d25b7f0efb14d579ed291d3bae78e/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string216 = /c2016dbd1bce8c6e38097264c6e0f96a55858c57dcee4e9d53be6d1a6e4705c9/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string217 = /c5ef421298667571d96c2156513742a66190742639400dae14232e2d802470aa/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string218 = /cb1995529b5d234699ede8dd41de77848b2ab6ffb43e3c150aba987f44a38779/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string219 = /cb2ca98c55b3128b2ba07b17243f67fb68ccba99a6d4476480cdf80741b2eda0/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string220 = /cc19a3679601e440635849d43a38421ec3fff94013496911ef69b9c7d601572b/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string221 = /cd4104d015dd44e17397a87018f35850f0363f089b3232e5306addbd2b6b807a/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string222 = /ce820866d58afd4f191053c7871032a69a3b7cf923ec47996738a151ddc61254/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string223 = /ceb602555ade094f60b02d5b68f2d76efa615cd1bfb05de20a6452e496353fc2/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string224 = /cmd\s\/c\sstart\shttps\:\/\/github\.com\/trustedsec\/specula\// nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string225 = /d163f8bb6aef4d8acca03431abdee92c3d104b2ae7dea5082d1a6b579e05dc77/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string226 = /d18e9a06ca8ad06c8b7178a31b1c6375031e75f08f3fb346a5fee42e2517ab88/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string227 = /d36e479529f169aeb563134d5ded662aed0e9d5ce15a357d2a2832370e1cce0c/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string228 = /d76d13a9b90ecf3be14037f420316c75b29a9b2d5f959465ec5459db61442d47/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string229 = /d780a0a408b42bcfbb25fbd591b2396b808aaba7b8358b5543afa3be342023d6/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string230 = /dcff5e7b030398229d694241415d632ccba115af4846926d16284475d4845236/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string231 = /e24dd6d8fb7ae3f556d3a64acf5627d210e92f4ca2e9473278b7273d21a696b3/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string232 = /e409a2e884393295c0b3c0e46b918c4b96ce535bbb9c5f81a21946198f6615cf/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string233 = /e6ea83ec183d2123c354aa88cc300927ab7fa5a99e9201e01c85caace559a536/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string234 = /e786a45fe464db32262fe83cdefe7728a80c9eb74ff27116b95ab944847f3de4/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string235 = /e9d37aeb31773787ae50b45e2a923edd31be7f27d1ff0ed5ee3bad45076d03d9/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string236 = /ec61e1fbfdc25380e23baadc18f997d45e27904d16008942de78dc55541a8e0f/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string237 = /ece36280c87bd6fdfd68a6e5daa3381aef5e79d9738db350f4dff8e55cc5090b/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string238 = /efaca1f25f45be0e5e1dc4dc4e8827049457bbc725a4779ccf9a4a71e1763aa7/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string239 = /execute\/host\/spawnproc_explorer/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string240 = /explorer\s\/root\,c\:\\windows\\system32\\sdclt\.exe/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string241 = /f036df2efba311e876debab785e546149cb15021ffa32294faea444ae499561e/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string242 = /f0e56c67cdf3a1f4dfc21bcff9d9e760e72fe34ebd32ab7ea0f1be9fc7e05e75/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string243 = /f20a1b4cdc2caf7baa975c8be3343063b5c819bda30807ffec6cddf822842c6a/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string244 = /f4653728eb40feedcce8ea91c19f00403651514c1c82c9c34c2b5e6ffb4bc7a9/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string245 = /f782f45b12b4185bb97a35da2fac19b3bff53b2b6f98617cc130e756b37f92d4/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string246 = /fa58b987e702e4213705ec9bfa01955f9cf4f5f4b8c43e91344bd8f997f83712/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string247 = /ff7a4f0dc724475fe15401ead0558667cea2b83113553486e74aacee031f17ae/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string248 = /ffa977849b2f8509e10dc873414ea6eba69531b901f932c8583478d215de863d/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string249 = /ffbdae1e47e2a86fb9791a70eb4e0840b15939f89ef7ba4bd80b6f8bf46a863e/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string250 = /from\slib\.core\.specmodule\simport\sSpecModule/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string251 = /Full\surl\s\-\sex\shttps\:\/\/hashcapture\.com/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string252 = /Function\slist_localadmins\(\)/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string253 = /hiddenFunctions\\upload_file\.py/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string254 = /https\:\/\/github\.com\/trustedsec\/specula\/wiki\/Why\-am\-I\-seeing\-this/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string255 = /https\:\/\/hashcapture\.com\// nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string256 = /MIIDBzCCAe\+gAwIBAgIJAINGOZrDXvI2MA0GCSqGSIb3DQEBCwUAMCcxJTAjBgNV/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string257 = /MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvmG0yhEe7dfN\+/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string258 = /Mozilla\/5\.0\s\(compatible\;\sMSIE\s10\.0\;\sWindows\sNT\s10\.0\;\sWOW64\;\sTrident\/7\.0\;\sSpecula\;\sMicrosoft\sOutlook/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string259 = /peration\/registry\/getallvaluesregistry/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string260 = /PUSH_CONNECTION_OUTSIDESPECULA/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string261 = /SELECT\s.{0,100}\sFROM\sWin32_GroupUser\sWHERE\sGroupComponent\=Win32_Group\.Domain\=VARIABLE\,Name\=\'Administrators\'/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string262 = /set\swebserver_address\shashcapture\.com/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string263 = /Specula\sC2/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string264 = /SpeculaC2/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string265 = /trustedsec\/specula/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string266 = /usemodule\soperation\/file\/put_file/ nocase ascii wide
        // Description: Specula is a C2 framework that allows for interactive operations of an implant that runs purely in the context of outlook
        // Reference: https://github.com/trustedsec/specula
        $string267 = /Your\sspeaktext\swas\ssent\sto\sthe\sspeaker\sas\svoice\.\sMohahaha/ nocase ascii wide
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
