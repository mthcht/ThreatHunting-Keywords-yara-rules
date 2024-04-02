rule LaZagne
{
    meta:
        description = "Detection patterns for the tool 'LaZagne' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LaZagne"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string1 = /\slaZagne\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string2 = /\smemorydump\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string3 = /\"The\sLaZagne\sproject\"/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string4 = /\/creddump7.{0,1000}\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string5 = /\/LaZagne\.git/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string6 = /\/laZagne\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string7 = /\/memorydump\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string8 = /\/pswRecovery4Moz\.txt/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string9 = /0cb85b94cf22a5eb8c6a391c9546aeeb1d86b7e7ae482b512de0f45c3ed90f26/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string10 = /0cf8787b1bfb746c629b92dc5a471a436105e176d306a2808a636adab4df1508/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string11 = /14268f4b4154d80f6c8a20bd79cca08e829cfef4d5f5c244d968c3652da7a336/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string12 = /26e18c8672146105fd4aed794f8d2305c635117eaea1de3e30b8f91473449b86/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string13 = /32ae965a0b8ea94499ffb0368ae4d5a349f84c5b37ba3cba1874d0bd73dc650c/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string14 = /3cc5ee93a9ba1fc57389705283b760c8bd61f35e9398bbfa3210e2becf6d4b05/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string15 = /3d2b4aa76b770b3421f0867aa68b42a1a17f723df251d81af9459f3a872a6fc4/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string16 = /4347d68bd769cf25fa1046b8c9c3f5f4c1c83ae6b96ac1d3ed4b8dce7647c22c/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string17 = /44acd66093e5cc54cdd68c183815d7c16b48b82aadd03c03bb01f3e03adf17c1/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string18 = /5312f40c37c8be83b7131d03100ca39c7e9862465dd40e62d13f153e4ddf1905/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string19 = /58cd6577c12f1c12a51e8abbe80aa54cd358e7c65a4efa8f28425d98ff0278cc/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string20 = /5a2e947aace9e081ecd2cfa7bc2e485528238555c7eeb6bcca560576d4750a50/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string21 = /6448c50a9a80154c2f1ca5b7525ffc8822f16562b1774a54efd066fcc80620e8/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string22 = /760980ec830603bf3bee659f92e939d2af88eef7bc50c2911cce1a41d35d881d/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string23 = /76d64e0cf551962a2ba20813933207dd398d1d06383c27765874219642218eca/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string24 = /7c9132c6c40c456396370d2e9cec4ee32b8cd289b29ccca946ea79f185eeaeed/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string25 = /853d769d63efcbc5d78f3f81c7cae176bf34c248d3bbbf6f32b4bc5d5de561e8/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string26 = /8b081e47fc6d4ab5dc0483dcc7243ff66911b9e660ab8ad9296a7144e95dbd47/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string27 = /8e068fd6cafac177fcf10e61a2672c0e572180bc20270e47e55525ad027d729d/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string28 = /98ad711010195669ee57216b2b376e81fec7437ceab10ab369fee7598d931a1a/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string29 = /9c46104f36627ea0842bf00c050e6fb43befa60e56369e7d4ea843a198e16323/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string30 = /AlessandroZ\/LaZagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string31 = /Application\.Lazagne\.H/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string32 = /b3c2a6fe40c1c3688b2ea12b7211a3573f1fcfb0fc092e20826db40f8a2fba63/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string33 = /c03ef8106c58c8980b7859e0a8ee2363d70e2b7f1346356127c826faf2c0caa3/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string34 = /c3b7a095eb5860b4414e354becc07bf30a9133737164b89b689873ee9f9c7bd6/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string35 = /dumping\spasswords\sfrom\s\%s\s\(pid\:/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string36 = /ed2f501408a7a6e1a854c29c4b0bc5648a6aa8612432df829008931b3e34bf56/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string37 = /fa8ff7e30ab51f8331ad6d9792d470406de52d66681c2b788361eb578558f913/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string38 = /fd0571eeb3d23326429a47df6b1104383efca78191f36099897ec29e5a4da50e/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string39 = /Hacktool\.Lazagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string40 = /HTool\-Lazagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string41 = /laZagne\.exe\sbrowsers/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string42 = /Lazagne\.exe/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string43 = /Lazagne\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string44 = /lazagne\.softwares\.sysadmin\.aws/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string45 = /lazagne\.softwares\.windows/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string46 = /lazagne\.tar\.gz/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string47 = /LaZagne\-master\.zip/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string48 = /memory.{0,1000}mimipy\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string49 = /memory\/onepassword\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string50 = /memorydump\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string51 = /mimipy\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string52 = /Trojan\.Lazagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string53 = /Win32\.LaZagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string54 = /Win64\.Lazagne/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string55 = /windows.{0,1000}lsa_secrets\.py/ nocase ascii wide
        // Description: The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext   APIs   custom algorithms   databases   etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
        // Reference: https://github.com/AlessandroZ/LaZagne
        $string56 = /Windows\/lazagne\.spec/ nocase ascii wide

    condition:
        any of them
}
