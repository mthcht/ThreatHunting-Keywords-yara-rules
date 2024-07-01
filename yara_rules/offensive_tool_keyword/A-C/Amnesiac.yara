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
        $string1 = /\s\/HiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string2 = /\s\\HiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string3 = /\sAmnesiac\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string4 = /\sAsk4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string5 = /\sAsk4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string6 = /\sAuthor\:\sRob\sLP\s\(\@L3o4j\)/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string7 = /\sDpapi\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string8 = /\sdumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string9 = /\s\-ep\sBypass\s\-enc\s\$b64FileServerMonitoringScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string10 = /\sHiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string11 = /\sInvoke\-GrabTheHash/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string12 = /\sInvoke\-Patamenia/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string13 = /\sInvoke\-WMIRemoting\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string14 = /\sklg\.ps1\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string15 = /\sLocalAdminAccess\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string16 = /\s\-Method\sPSRemoting\s\-Command\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string17 = /\sPassSpray\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string18 = /\ssecrets\sfound\sfor\sDPAPI_SYSTEM/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string19 = /\s\-Steal\s\-ProcessID\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string20 = /\$CertutilDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string21 = /\/Amnesiac\.git/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string22 = /\/Amnesiac\.git/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string23 = /\/Amnesiac\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string24 = /\/Ask4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string25 = /\/Ask4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string26 = /\/Dpapi\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string27 = /\/dumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string28 = /\/dumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string29 = /\/Ferrari\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string30 = /\/File\-Server\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string31 = /\/HiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string32 = /\/klg\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string33 = /\/NETAMSI\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string34 = /\/NETAMSI\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string35 = /\/PassSpray\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string36 = /\/RDPKeylog\.exe/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string37 = /\/Suntour\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string38 = /\/TakeMyRDP2\.0/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string39 = /\[\+\]\sAsk4Creds\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string40 = /\[\+\]\sCreating\sService\son\sRemote\sTarget\?/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string41 = /\[\+\]\sDomain\sPassword\sSpray\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string42 = /\[\+\]\sDpapiDump\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string43 = /\[\+\]\sDpapiDump\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string44 = /\[\+\]\sHiveDump\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string45 = /\[\+\]\sHiveDump\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string46 = /\[\+\]\sInvoke\-DCSync\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string47 = /\[\+\]\sInvoke\-GrabTheHash\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string48 = /\[\+\]\sKeylog\ssaved\sto\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string49 = /\[\+\]\sKeylogger\sstarted\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string50 = /\[\+\]\sKeylogger\sstarted\swith\sPID\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string51 = /\[\+\]\sMimi\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string52 = /\[\+\]\sPayload\sformat\:\spwsh/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string53 = /\[\+\]\sPInject\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string54 = /\[\+\]\sPowershellKerberos\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string55 = /\[\+\]\sPowerView\sLoaded\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string56 = /\[\+\]\sPowerView\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string57 = /\[\+\]\sRDP\sKeylog\ssaved\sto\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string58 = /\[\+\]\sRDP\sKeylog\ssaved\sto\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string59 = /\[\+\]\sRDP\sKeylogger\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string60 = /\[\+\]\sRDP\sKeylogger\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string61 = /\[\+\]\sRDP\sKeylogger\sstarted\swith\sPID\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string62 = /\[\+\]\sRubeus\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string63 = /\[\+\]\sRubeus\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string64 = /\[\+\]\sSMBRemoting\sand\sWMIRemoting\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string65 = /\[\+\]\sSucessfully\sinjected\sthe\sshellcode\sinto\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string66 = /\[\+\]\sToken\-Impersonation\sLoaded/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string67 = /\[Find\-DomainUserLocation\]\sStealth\senumeration\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string68 = /\[Find\-InterestingDomainShareFile\]\sEnumerating\sserver/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string69 = /\[Get\-DomainGPOUserLocalGroupMapping\]\sEnumerating\snested\sgroup\smemberships\sfor/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string70 = /\[Invoke\-RevertToSelf\]\sToken\simpersonation\ssuccessfully\sreverted/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string71 = /\[Invoke\-UserImpersonation\]\sAlternate\scredentials\ssuccessfully\simpersonated/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string72 = /\\Amnesiac\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string73 = /\\Amnesiac\-main\\/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string74 = /\\Ask4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string75 = /\\Ask4Creds\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string76 = /\\Dpapi\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string77 = /\\dumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string78 = /\\dumper\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string79 = /\\Ferrari\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string80 = /\\File\-Server\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string81 = /\\File\-Server\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string82 = /\\HiveDump\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string83 = /\\klg\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string84 = /\\LocalAdminAccess\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string85 = /\\LocalAdminAccess\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string86 = /\\NETAMSI\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string87 = /\\NETAMSI\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string88 = /\\PassSpray\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string89 = /\\PInject\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string90 = /\\RDPKeylog\.exe/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string91 = /\\Suntour\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string92 = /\\TakeMyRDP\.pdb/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string93 = /\\TGT_Monitor\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string94 = /\\Token\-Impersonation\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string95 = /\\Users\\Public\\Documents\\\$\(\$env\:USERNAME\)log\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string96 = /0c509e431004929c0aaa10ba671db16a8d02003ac17419fdc31687bf9747e4b6/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string97 = /16337f81bede48a56cba8329bfe3cf02153c96d1e3650112ecdb03f58b25b17d/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string98 = /19f46bd0cecc1c03859e2a19b2041f6538f4e43aa3124b3eaaec00767381935f/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string99 = /1fe92c614cbb39738a9726a5d970ac526f579b7e146c65ecd02cf6d4e7d563c1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string100 = /24d7bda466850d93fc1883a3937e1317fbb3f9e631ab0d2a4fa0b45c2c21c24f/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string101 = /31218c2e08ddf852de490f4d48d3d5751c3bc66ae9a73c815421dd20cd6b748e/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string102 = /3c2ff027b13ba2b710d9ce7055cebd5e220b2713b12c765598bf0bcef9dc3cef/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string103 = /3xpl01tc0d3r\/ProcessInjection/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string104 = /3xpl01tc0d3r\/ProcessInjection/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string105 = /5062dae017d539693b9e6cef1cf8018aa4963b6a01ef2614cff020fd85f8ba07/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string106 = /678ce24e\-70c4\-47b1\-b595\-ca0835ba35d9/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string107 = /6997588d3c194d5a1d3c32ae3e2fe1475374dfe0c5845485d550796440621bbb/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string108 = /6b49ab14afa0c2764f31c768dcc45b7efee3967d3cd4f572c4bb99cc4e128c38/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string109 = /6d6629cbd6d624b1a977decf53adbb0e2fb46a07d8ac7392324572dbafe26d48/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string110 = /796f70f040f3edcf0b48a711ad9ebce5a1f1dbbad15195d577e9c19c04fd0b88/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string111 = /8db1d4921a94819ac9222d02e9db1539d2fe613f0fe0459698f3daa3d56d934e/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string112 = /902337b62862f99bbf97131701eaab2be82fd5a84b7d379cec0acff56a2bf670/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string113 = /a3bf479adb8b6bd523617d51a5c872f86d0a1d2104e63749830b2bd254567d80/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string114 = /aa013dcded3e67135ec91768764bc46d0509c78f061134e1a7917603fff3d6a8/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string115 = /Access_Check\s\-Method\sPSRemoting/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string116 = /ae219371bbfc41040dc9150b688271b9cd51cb325e4c328f954a6b474dfb019d/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string117 = /Amnesiac\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string118 = /Amnesiac\-main\.zip/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string119 = /b8b0e6a5452420520359221d8f527a35ec6b4da45f55179a1ffd5b820d1c35dc/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string120 = /be3345a2cedd13aae147564426bb743332b2053868ba7c3e64f14c247416f86c/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string121 = /c\:\\Users\\Public\\Documents\\log\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string122 = /c66bc18ad7289d0a5a0cf3e627566e0871cb230d6f3a2f3ede5948ebd18f2b48/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string123 = /c71270964c15f42df8e82477be2e7c833c947f7be29f1ee269835b06360bc5d5/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string124 = /d04cd33cbf5406ac9d9ecfef2276fa1188526125f52c01233542c701f624d7a5/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string125 = /eef2ceac990c985faaa8e869e66e47652863bd94a14a87de4245996111717326/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string126 = /f0d99239fa828a18f0756ec717a663b5e64af9cf4e4130ec0a27bdf5d592ac96/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string127 = /f7a755d30fe841ce34b0ef2f4bd3265fab3623945636267c3d5d67c111a9a2a3/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string128 = /Find\-InterestingDomainAcl/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string129 = /Find\-InterestingDomainShareFile/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string130 = /Find\-LocalAdminAccess\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string131 = /Find\-LocalAdminAccess\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string132 = /Find\-LocalAdminAccess\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string133 = /function\sAmnesiac\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string134 = /Get\-DomainSPNTicket\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string135 = /Get\-Item\s\-Path\s\"HKLM\:\\SOFTWARE\\Microsoft\\Windows\sDefender\\Exclusions\\Paths/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string136 = /Get\-RegLoggedOn\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string137 = /Get\-WMIRegCachedRDPConnection\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string138 = /GhostPack\/Rubeus/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string139 = /iex\(new\-object\snet\.webclient\)\.downloadstring\(.{0,1000}\/pwv\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string140 = /Invoke\-DCSync\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string141 = /Invoke\-DCSync/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string142 = /Invoke\-DCSync\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string143 = /Invoke\-DpapiDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string144 = /Invoke\-GrabTheHash/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string145 = /Invoke\-HiveDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string146 = /Invoke\-HiveDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string147 = /Invoke\-Kerberoast/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string148 = /Invoke\-Kirby/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string149 = /Invoke\-Kirby/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string150 = /Invoke\-LSADump\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string151 = /Invoke\-LSADump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string152 = /Invoke\-PassSpray/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string153 = /Invoke\-PassSpray/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string154 = /Invoke\-Patamenia\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string155 = /Invoke\-RevertToSelf/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string156 = /Invoke\-SAMDump\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string157 = /Invoke\-SAMDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string158 = /Invoke\-SessionHunter/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string159 = /Invoke\-SessionHunter\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string160 = /Invoke\-SMBRemoting/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string161 = /Invoke\-SMBRemoting\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string162 = /Invoke\-WMIRemoting/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string163 = /leo4j\.gitbook\.io\/amnesiac/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string164 = /Leo4j\/Amnesiac/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string165 = /Leo4j\/Amnesiac/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string166 = /MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string167 = /MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string168 = /msfvenom\s\-p\swindows\/x64\/exec/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string169 = /MzHmO\/PowershellKerberos/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string170 = /PassSpray\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string171 = /powershell\.exe\s\-enc\s\$B64ServerScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string172 = /PowerView\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string173 = /quser\;net\ssessions\;query\ssession\;klist\ssessions/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string174 = /RDPKeylog\.exe/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string175 = /Remove\-Item\s\-Path\s.{0,1000}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history\.txt/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string176 = /Rubeus\screatenetonly\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string177 = /shell_smbadmin\s\-Targets\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string178 = /shell_tknadmin\s\-Domain\s.{0,1000}\s\-DomainController\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string179 = /shell_tknadmin\s\-Targets\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string180 = /shell_wmiadmin\s\-Domain\s.{0,1000}\s\-DomainController/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string181 = /ShellGen\spowershell\.exe\s\-ep\sbypass\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string182 = /Spray\san\sempty\spassword\sacross\sthe\sDomain/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string183 = /TGT_Monitor\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string184 = /Tkn_Access_Check\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string185 = /tmenochet\/PowerDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string186 = /tmenochet\/PowerDump/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string187 = /Token\-Impersonation\s\-MakeToken\s\-Username\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string188 = /Token\-Impersonation\s\-Rev2Self/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string189 = /Token\-Impersonation\s\-Rev2Self/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string190 = /Token\-Impersonation\s\-Steal/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string191 = /Token\-Impersonation\.ps1/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string192 = /vletoux\/MakeMeEnterpriseAdmin/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string193 = /wevtutil\sel\s\|\sForEach\-Object\s\{wevtutil\scl\s/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string194 = /\-WindowS\sHidden\s\-ep\sBypass\s\-enc\s\$b64FileServerMonitoringScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string195 = /\-WindowS\sHidden\s\-ep\sBypass\s\-enc\s\$b64monitoringScript/ nocase ascii wide
        // Description: Amnesiac is a post-exploitation framework entirely written in PowerShell and designed to assist with Lateral Movement within Active Directory environments
        // Reference: https://github.com/Leo4j/Amnesiac
        $string196 = /wmic\sstartup\sget\sCaption\,Command\,Location\,User/ nocase ascii wide

    condition:
        any of them
}
