rule Amnesiac
{
    meta:
        description = "Detection patterns for the tool 'Amnesiac' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amnesiac"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string1 = /\sAmnesiac\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string2 = /\sAsk4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string3 = /\sAuthor\:\sRob\sLP\s\(\@L3o4j\)/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string4 = /\sDpapi\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string5 = /\sdumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string6 = /\s\-ep\sBypass\s\-enc\s\$b64FileServerMonitoringScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string7 = /\sHiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string8 = " Invoke-GrabTheHash" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string9 = " Invoke-Patamenia" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string10 = /\sInvoke\-WMIRemoting\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string11 = /\sklg\.ps1\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string12 = /\sLocalAdminAccess\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string13 = " -Method PSRemoting -Command " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string14 = /\sPassSpray\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string15 = " secrets found for DPAPI_SYSTEM" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string16 = " -Steal -ProcessID " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string17 = /\$CertutilDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string18 = /\$HidePayload/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string19 = /\$shellcode\s\+\=\s0x65\,0x48\,0x8b\,0x42\,0x60/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string20 = /\/Amnesiac\.git/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string21 = /\/Amnesiac\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string22 = /\/Ask4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string23 = /\/Dpapi\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string24 = /\/dumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string25 = /\/Ferrari\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string26 = /\/File\-Server\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string27 = /\/HiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string28 = /\/HiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string29 = /\/klg\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string30 = /\/NETAMSI\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string31 = /\/PassSpray\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string32 = /\/RDPKeylog\.exe/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string33 = /\/Suntour\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string34 = /\/TakeMyRDP2\.0/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string35 = /\[\+\]\sAsk4Creds\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string36 = /\[\+\]\sCreating\sService\son\sRemote\sTarget\?/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string37 = /\[\+\]\sDomain\sPassword\sSpray\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string38 = /\[\+\]\sDpapiDump\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string39 = /\[\+\]\sDpapiDump\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string40 = /\[\+\]\sHiveDump\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string41 = /\[\+\]\sHiveDump\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string42 = /\[\+\]\sInvoke\-DCSync\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string43 = /\[\+\]\sInvoke\-GrabTheHash\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string44 = /\[\+\]\sKeylog\ssaved\sto\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string45 = /\[\+\]\sKeylogger\sstarted\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string46 = /\[\+\]\sKeylogger\sstarted\swith\sPID\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string47 = /\[\+\]\sMimi\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string48 = /\[\+\]\sPayload\sformat\:\spwsh/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string49 = /\[\+\]\sPInject\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string50 = /\[\+\]\sPowershellKerberos\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string51 = /\[\+\]\sPowerView\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string52 = /\[\+\]\sPowerView\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string53 = /\[\+\]\sRDP\sKeylog\ssaved\sto\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string54 = /\[\+\]\sRDP\sKeylogger\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string55 = /\[\+\]\sRDP\sKeylogger\sstarted\swith\sPID\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string56 = /\[\+\]\sRubeus\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string57 = /\[\+\]\sSMBRemoting\sand\sWMIRemoting\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string58 = /\[\+\]\sSucessfully\sinjected\sthe\sshellcode\sinto\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string59 = /\[\+\]\sToken\-Impersonation\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string60 = /\[Find\-DomainUserLocation\]\sStealth\senumeration\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string61 = /\[Find\-InterestingDomainShareFile\]\sEnumerating\sserver/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string62 = /\[Get\-DomainGPOUserLocalGroupMapping\]\sEnumerating\snested\sgroup\smemberships\sfor/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string63 = /\[Invoke\-RevertToSelf\]\sToken\simpersonation\ssuccessfully\sreverted/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string64 = /\[Invoke\-UserImpersonation\]\sAlternate\scredentials\ssuccessfully\simpersonated/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string65 = /\\Amnesiac\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string66 = /\\Amnesiac\-main\\/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string67 = /\\Ask4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string68 = /\\Dpapi\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string69 = /\\dumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string70 = /\\Ferrari\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string71 = /\\File\-Server\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string72 = /\\File\-Server\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string73 = /\\HiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string74 = /\\klg\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string75 = /\\LocalAdminAccess\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string76 = /\\NETAMSI\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string77 = /\\NETAMSI\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string78 = /\\PInject\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string79 = /\\Public\\Documents\\Amnesiac/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string80 = /\\RDPKeylog\.exe/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string81 = /\\Suntour\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string82 = /\\TakeMyRDP\.pdb/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string83 = /\\TGT_Monitor\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string84 = /\\Token\-Impersonation\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string85 = /\\Users\\Public\\Documents\\\$\(\$env\:USERNAME\)log\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string86 = "0c509e431004929c0aaa10ba671db16a8d02003ac17419fdc31687bf9747e4b6" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string87 = "16337f81bede48a56cba8329bfe3cf02153c96d1e3650112ecdb03f58b25b17d" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string88 = "19f46bd0cecc1c03859e2a19b2041f6538f4e43aa3124b3eaaec00767381935f" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string89 = "1fe92c614cbb39738a9726a5d970ac526f579b7e146c65ecd02cf6d4e7d563c1" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string90 = "24d7bda466850d93fc1883a3937e1317fbb3f9e631ab0d2a4fa0b45c2c21c24f" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string91 = "31218c2e08ddf852de490f4d48d3d5751c3bc66ae9a73c815421dd20cd6b748e" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string92 = "3c2ff027b13ba2b710d9ce7055cebd5e220b2713b12c765598bf0bcef9dc3cef" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string93 = "3xpl01tc0d3r/ProcessInjection" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string94 = "5062dae017d539693b9e6cef1cf8018aa4963b6a01ef2614cff020fd85f8ba07" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string95 = "678ce24e-70c4-47b1-b595-ca0835ba35d9" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string96 = "6997588d3c194d5a1d3c32ae3e2fe1475374dfe0c5845485d550796440621bbb" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string97 = "6b49ab14afa0c2764f31c768dcc45b7efee3967d3cd4f572c4bb99cc4e128c38" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string98 = "6d6629cbd6d624b1a977decf53adbb0e2fb46a07d8ac7392324572dbafe26d48" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string99 = "796f70f040f3edcf0b48a711ad9ebce5a1f1dbbad15195d577e9c19c04fd0b88" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string100 = "8db1d4921a94819ac9222d02e9db1539d2fe613f0fe0459698f3daa3d56d934e" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string101 = "902337b62862f99bbf97131701eaab2be82fd5a84b7d379cec0acff56a2bf670" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string102 = "a3bf479adb8b6bd523617d51a5c872f86d0a1d2104e63749830b2bd254567d80" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string103 = "aa013dcded3e67135ec91768764bc46d0509c78f061134e1a7917603fff3d6a8" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string104 = "Access_Check -Method PSRemoting" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string105 = "ae219371bbfc41040dc9150b688271b9cd51cb325e4c328f954a6b474dfb019d" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string106 = /Amnesiac\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string107 = /Amnesiac_ShellReady\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string108 = /Amnesiac\-main\.zip/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string109 = "b8b0e6a5452420520359221d8f527a35ec6b4da45f55179a1ffd5b820d1c35dc" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string110 = "be3345a2cedd13aae147564426bb743332b2053868ba7c3e64f14c247416f86c" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string111 = /c\:\\Users\\Public\\Documents\\log\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string112 = "c66bc18ad7289d0a5a0cf3e627566e0871cb230d6f3a2f3ede5948ebd18f2b48" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string113 = "c71270964c15f42df8e82477be2e7c833c947f7be29f1ee269835b06360bc5d5" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string114 = "cmd /c powershell -windowst hidden " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string115 = /cmd\.exe\s\/c\spowershell\.exe\s\-enc\s\$b64ClientScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string116 = /cmd\.exe\s\/c\spowershell\.exe\s\-enc\s\$B64ServerScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string117 = /cmd\.exe.{0,1000}\/c\spowershell\s\-windowst\shidden\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string118 = "d04cd33cbf5406ac9d9ecfef2276fa1188526125f52c01233542c701f624d7a5" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string119 = "df354b2e87294f8b650fc5f43b3f4ec1ac2aa193e5d67f63a42887f77fa1aad5" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string120 = "eef2ceac990c985faaa8e869e66e47652863bd94a14a87de4245996111717326" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string121 = "f0d99239fa828a18f0756ec717a663b5e64af9cf4e4130ec0a27bdf5d592ac96" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string122 = "f7a755d30fe841ce34b0ef2f4bd3265fab3623945636267c3d5d67c111a9a2a3" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string123 = "Find-InterestingDomainAcl" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string124 = "Find-InterestingDomainShareFile" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string125 = "Find-LocalAdminAccess " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string126 = /Find\-LocalAdminAccess\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string127 = "function Amnesiac " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string128 = "Get-DomainSPNTicket " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string129 = /Get\-Item\s\-Path\s\\"HKLM\:\\SOFTWARE\\Microsoft\\Windows\sDefender\\Exclusions\\Paths/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string130 = "Get-RegLoggedOn " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string131 = "Get-WMIRegCachedRDPConnection " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string132 = "GhostPack/Rubeus" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string133 = /iex\(new\-object\snet\.webclient\)\.downloadstring\(.{0,1000}\/pwv\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string134 = "Invoke-DCSync" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string135 = /Invoke\-DCSync\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string136 = "Invoke-DpapiDump" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string137 = "Invoke-GrabTheHash" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string138 = "Invoke-HiveDump" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string139 = "Invoke-HiveDump" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string140 = "Invoke-Kerberoast" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string141 = "Invoke-Kirby" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string142 = "Invoke-LSADump " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string143 = "Invoke-LSADump" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string144 = "Invoke-PassSpray" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string145 = "Invoke-PassSpray" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string146 = /Invoke\-Patamenia\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string147 = "Invoke-RevertToSelf" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string148 = "Invoke-SAMDump " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string149 = "Invoke-SAMDump" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string150 = "Invoke-SessionHunter" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string151 = /Invoke\-SessionHunter\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string152 = "Invoke-SMBRemoting" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string153 = /Invoke\-SMBRemoting\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string154 = "Invoke-WMIRemoting" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string155 = /leo4j\.gitbook\.io\/amnesiac/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string156 = "Leo4j/Amnesiac" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string157 = /MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string158 = "msfvenom -p windows/x64/exec" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string159 = "MzHmO/PowershellKerberos" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string160 = /PassSpray\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string161 = /powershell\.exe\s\-enc\s\$B64ServerScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string162 = /PowerView\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string163 = "quser;net sessions;query session;klist sessions" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string164 = /RDPKeylog\.exe/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string165 = /Remove\-Item\s\-Path\s.{0,1000}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string166 = "Rubeus createnetonly " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string167 = "shell_smbadmin -Targets " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string168 = /shell_tknadmin\s\-Domain\s.{0,1000}\s\-DomainController\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string169 = "shell_tknadmin -Targets " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string170 = /shell_wmiadmin\s\-Domain\s.{0,1000}\s\-DomainController/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string171 = /ShellGen\spowershell\.exe\s\-ep\sbypass\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string172 = "Spray an empty password across the Domain" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string173 = /TGT_Monitor\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string174 = /Tkn_Access_Check\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string175 = "tmenochet/PowerDump" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string176 = "Token-Impersonation -MakeToken -Username " nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string177 = "Token-Impersonation -Rev2Self" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string178 = "Token-Impersonation -Steal" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string179 = /Token\-Impersonation\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string180 = "vletoux/MakeMeEnterpriseAdmin" nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string181 = /wevtutil\sel\s\|\sForEach\-Object\s\{wevtutil\scl\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string182 = /\-WindowS\sHidden\s\-ep\sBypass\s\-enc\s\$b64FileServerMonitoringScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string183 = /\-WindowS\sHidden\s\-ep\sBypass\s\-enc\s\$b64monitoringScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string184 = "wmic startup get Caption,Command,Location,User" nocase ascii wide

    condition:
        any of them
}
