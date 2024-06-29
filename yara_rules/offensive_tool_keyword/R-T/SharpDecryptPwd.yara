rule SharpDecryptPwd
{
    meta:
        description = "Detection patterns for the tool 'SharpDecryptPwd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDecryptPwd"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string1 = /\.exe\sXmanager\s\/user\:.{0,1000}\s\/sid\:.{0,1000}\s\/path\:.{0,1000}/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string2 = /\.exe\s\-Xmangager\s\-p\s/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string3 = /\/SharpDecryptPwd\.git/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string4 = /\\FoxmailDump\.cpp/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string5 = /\\SharpDecryptPwd\.sln/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string6 = /\\SharpDecryptPwd\\/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string7 = /\\SharpDecryptPwd\-main/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string8 = /\>SharpDecryptPwd\</ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string9 = /1824ED63\-BE4D\-4306\-919D\-9C749C1AE271/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string10 = /1f385acf11f8ea6673d7295be6492ea9913b525da25dcc037ea49ef4f86a9d58/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string11 = /2273f47d253c1974f82b9b7f9018228080e8ac41b75bba4e779fe9f918d72aa1/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string12 = /537dfda00b6ce57ca35f3da4eaac5cfc42c4180d5573673a66c4665517d0a208/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string13 = /80ed17895205205c5a769d18715cb74a623cee6a5379bb8142d2c8c533c759b2/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string14 = /RowTeam\/SharpDecryptPwd/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string15 = /SharpDecryptPwd\s/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string16 = /SharpDecryptPwd\.Commands/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string17 = /SharpDecryptPwd\.csproj/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string18 = /SharpDecryptPwd\.exe/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string19 = /SharpDecryptPwd\.exe/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string20 = /SharpDecryptPwd\.Lib/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string21 = /SharpDecryptPwd\.Properties/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string22 = /uknowsec\/SharpDecryptPwd/ nocase ascii wide
        // Description: Decrypt Navicat,Xmanager,Filezilla,Foxmail,WinSCP,etc
        // Reference: https://github.com/RowTeam/SharpDecryptPwd
        $string23 = /using\sSharpDecryptPwd/ nocase ascii wide

    condition:
        any of them
}
