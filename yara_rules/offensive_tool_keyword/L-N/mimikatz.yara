rule mimikatz
{
    meta:
        description = "Detection patterns for the tool 'mimikatz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimikatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: mimikatz default strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string1 = " Benjamin DELPY " nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string2 = /\sHo\,\shey\!\sI\'m\sa\sDC\s\:\)/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string3 = "' p::d '" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string4 = "' s::l '" nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string5 = /\!process\s0\s0\slsass\.exe/ nocase ascii wide
        // Description: removing process protection for the lsass.exe process can potentially enable adversaries to inject malicious code or manipulate the process to escalate privileges or gather sensitive information such as credentials. command: !processprotect /process:lsass.exe /remove
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string6 = /\!processprotect\s.{0,1000}lsass\.exe/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string7 = "\"A La Vie, A L'Amour\" - Windows build " nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string8 = /\%3u\s\-\sDirectory\s\'\%s\'\s\(.{0,1000}\.kirbi\)/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string9 = /\.kirbi\s/ nocase ascii wide
        // Description: Mimikatz Using domain trust key From the DC dump the hash of the currentdomain\targetdomain$ trust account using Mimikatz (e.g. with LSADump or DCSync). Then using this trust key and the domain SIDs. forge an inter-realm TGT using Mimikatz adding the SID for the target domains enterprise admins group to our SID history.
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string10 = /\/domain\:.{0,1000}\s\/sid\:.{0,1000}\s\/sids\:.{0,1000}\s\/rc4\:.{0,1000}\s\/user\:.{0,1000}\s\/service\:krbtgt\s\/target\:.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 script argument
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string11 = "/DumpCerts" nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 script argument
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string12 = "/DumpCreds" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/vyrus001/go-mimikatz
        $string13 = "/go-mimikatz" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string14 = /\/kiwi_passwords\.yar/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string15 = /\/mimi32\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string16 = /\/mimi64\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string17 = /\/mimicom\.idl/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string18 = /\/mimidrv\.sys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string19 = /\/mimidrv\.zip/ nocase ascii wide
        // Description: mimikatz github link
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string20 = /\/mimikatz\.git/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string21 = /\/mimikatz\.sln/ nocase ascii wide
        // Description: mimikatz archive link
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string22 = /\/mimikatz\/archive\/master\.zip/ nocase ascii wide
        // Description: mimikatz archive link
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string23 = "/mimikatz/releases/" nocase ascii wide
        // Description: mimikatz archive link
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string24 = "/mimikatz/zipball/" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string25 = /\/mimikatz_bypass\/mimikatz\.py/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string26 = /\/mimikatz_bypass\/mimikatz2\.py/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string27 = /\/mimikatz_bypassAV\/main\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string28 = /\/mimikatz_bypassAV\/mimikatz_load\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string29 = /\/mimikatz_load\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string30 = /\/mimilib\.def/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string31 = /\/mimilove\.c/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string32 = /\/mimilove\.h/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string33 = /\/mimilove\.rc/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/skelsec/pypykatz
        $string34 = /\/pypykatz\.py/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string35 = "/rakjong/mimikatz_bypassAV/" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/skelsec/pypykatz
        $string36 = "/skelsec/pypykatz" nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string37 = /\[experimental\]\sExtract\skeys\sfrom\sCAPI\sRSA\/AES\sprovider/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string38 = /\[experimental\]\sPatch\sCNG\sservice\sfor\seasy\sexport/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string39 = /\[experimental\]\sPatch\sCryptoAPI\slayer\sfor\seasy\sexport/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string40 = /\[experimental\]\spatch\sEvents\sservice\sto\savoid\snew\sevents/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string41 = /\[experimental\]\spatch\sTerminal\sServer\sservice\sto\sallow\smultiples\susers/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string42 = /\[experimental\]\sTry\sto\senumerate\sall\smodules\swith\sDetours\-like\shooks/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string43 = /\[experimental\]\stry\sto\sget\spasswords\sfrom\smstsc\sprocess/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string44 = /\[experimental\]\stry\sto\sget\spasswords\sfrom\srunning\ssessions/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string45 = /\\\\\.\\mimidrv/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string46 = /\\Device\\mimidrv/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string47 = /\\DosDevices\\mimidrv/ nocase ascii wide
        // Description: mimikatz powershell alternative name
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string48 = /\\katz\.ps1/ nocase ascii wide
        // Description: mimikatz log files
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string49 = /\\kcredentialprovider\.log/ nocase ascii wide
        // Description: mimikatz log files
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string50 = /\\kiwidns\.log/ nocase ascii wide
        // Description: mimikatz log files
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string51 = /\\kiwifilter\.log/ nocase ascii wide
        // Description: mimikatz log files
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string52 = /\\kiwinp\.log/ nocase ascii wide
        // Description: mimikatz log files
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string53 = /\\kiwissp\.log/ nocase ascii wide
        // Description: mimikatz log files
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string54 = /\\kiwisub\.log/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string55 = /\\mimi32\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string56 = /\\mimi64\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string57 = /\\mimicom\.idl/ nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string58 = /\\mimidrv\.pdb/ nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string59 = /\<3\seo\.oe\s\~\sANSSI\sE\>/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string60 = /\<3\seo\.oe/ nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string61 = ">mimikatz for Windows<" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string62 = /\>mimikatz\.exe\</ nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string63 = /\>mimilib\.dll\</ nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string64 = ">mimilove for Windows 2000<" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string65 = ">mimilove<" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string66 = /\>mimispool\.dll\</ nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string67 = "02bb96ce1e3948500c9bfc51d925ca2f59a32a1ae9e4d871c6913988bdba35f6" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string68 = "02bb96ce1e3948500c9bfc51d925ca2f59a32a1ae9e4d871c6913988bdba35f6" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string69 = "032df02a828c74567c4659feb4fd6644726265e0f26456c467f46434923399ca" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string70 = "032df02a828c74567c4659feb4fd6644726265e0f26456c467f46434923399ca" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string71 = "05842de51ede327c0f55df963f6de4e32ab88f43a73b9e0e1d827bc70199eff0" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string72 = "05842de51ede327c0f55df963f6de4e32ab88f43a73b9e0e1d827bc70199eff0" nocase ascii wide
        // Description: mimikatz GUID project
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string73 = "0BD5DE6B-8DA5-4CF1-AE53-A265010F52AA" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string74 = "0c79c5147e4ff87b8b655873c328b10976a68e7226089c1a7ab09a6b74038b13" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string75 = "0c79c5147e4ff87b8b655873c328b10976a68e7226089c1a7ab09a6b74038b13" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string76 = "0cf9297dc4511e2957e45524ec12f8b6e9c4873cec625daf20d27aedc0bdf5e9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string77 = "0cf9297dc4511e2957e45524ec12f8b6e9c4873cec625daf20d27aedc0bdf5e9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string78 = "0d31a6d35d6b320f815c6ba327ccb8946d4d7f771e0dcdbf5aa8af775576f2d1" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string79 = "0d31a6d35d6b320f815c6ba327ccb8946d4d7f771e0dcdbf5aa8af775576f2d1" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string80 = "0db7123a79bba0227e8f91d34847ccee8be3edac266c38e804344b957486fdb9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string81 = "0db7123a79bba0227e8f91d34847ccee8be3edac266c38e804344b957486fdb9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string82 = "0db7123a79bba0227e8f91d34847ccee8be3edac266c38e804344b957486fdb9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string83 = "0db7123a79bba0227e8f91d34847ccee8be3edac266c38e804344b957486fdb9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string84 = "1027943da338f85a1aff09bb1825e4d4fe2579256cec951becbb5cebd5c60b72" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string85 = "1027943da338f85a1aff09bb1825e4d4fe2579256cec951becbb5cebd5c60b72" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string86 = "12debc3c0e9c84b1d7d5ddaf3fc907d2fc2c4f0e6d340875eb4bf468250d9625" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string87 = "12debc3c0e9c84b1d7d5ddaf3fc907d2fc2c4f0e6d340875eb4bf468250d9625" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string88 = "175c1d2aab217c0aba91cdc0366e8a81ed44e4fb8c9aa9109912ce488f364178" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string89 = "175c1d2aab217c0aba91cdc0366e8a81ed44e4fb8c9aa9109912ce488f364178" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string90 = "176528ecba1bee91a831b36e3829803526e329f755af06e6ab14b57ac51df58c" nocase ascii wide
        // Description: mimikatz UUID
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string91 = "17FC11E9-C258-4B8D-8D07-2F4125156244" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string92 = "19d22a57efb66f96f7c8aa0650cc42a93bda9074d263f37ad120f51061e6bbf1" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string93 = "1c8101652c99416535282e92882538ba9daee459abeb16c1fa1e3f6578a20367" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string94 = "1c8101652c99416535282e92882538ba9daee459abeb16c1fa1e3f6578a20367" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string95 = "1e8efe80176f832df2a27862795208571fae916c29e755447305178528bcd437" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string96 = "1e8efe80176f832df2a27862795208571fae916c29e755447305178528bcd437" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string97 = "1f2338d7b628374139d373af383a1bdec1a16b43ced015849c6be4e4d90cc2c3" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string98 = "1f7c4485debf950cfd5b7442d391d71de3bdc1b041993be5238847e7d6f50ba4" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string99 = "1f7c4485debf950cfd5b7442d391d71de3bdc1b041993be5238847e7d6f50ba4" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string100 = "203a17d5f5b9b71578a530294b19056d7fefa2660883c1389fce89d536e93950" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string101 = "22101aecc2195c323fdd0d949014c993790c425693f60c2bbc2138b4a830a519" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string102 = "22101aecc2195c323fdd0d949014c993790c425693f60c2bbc2138b4a830a519" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string103 = "2633f67803a9cdd6ba381d1ff7e334a1e0472dc86d6f81513e57003644e80780" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string104 = "2633f67803a9cdd6ba381d1ff7e334a1e0472dc86d6f81513e57003644e80780" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string105 = "274ca13168b38590c230bddc2d606bbe8c26de8a6d79156a6c7d07265efe0fdf" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string106 = "274ca13168b38590c230bddc2d606bbe8c26de8a6d79156a6c7d07265efe0fdf" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string107 = "274ca13168b38590c230bddc2d606bbe8c26de8a6d79156a6c7d07265efe0fdf" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string108 = "274ca13168b38590c230bddc2d606bbe8c26de8a6d79156a6c7d07265efe0fdf" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string109 = "27cc5348dd41818e79d5d87ee9d78e0f6ddc331f31c72ef0d4073f38d4fe4637" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string110 = "28e899105aafa4f17c8a0d81d2f6664926afe59ff8c35e076ba2976291521300" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string111 = "28e899105aafa4f17c8a0d81d2f6664926afe59ff8c35e076ba2976291521300" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string112 = "2a74704d6eb53e9a97c063f182021c51b5f687882227902e020ac82f45ab1e4c" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string113 = "2a74704d6eb53e9a97c063f182021c51b5f687882227902e020ac82f45ab1e4c" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string114 = "2ac9118877d2f38cfb75a17e0c0cb4ac845398e55588925fa775fc3fea93b319" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string115 = "2ac9118877d2f38cfb75a17e0c0cb4ac845398e55588925fa775fc3fea93b319" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string116 = "2c1873b4fdd1abde90702784cb5870a06c8fe662cfc428c018d9052c89421351" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string117 = "2c1873b4fdd1abde90702784cb5870a06c8fe662cfc428c018d9052c89421351" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string118 = "2e427f766b9421cc1873cdc07c3552d3ab457c9139db05b2440b23577ab97217" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string119 = "2e8ab836111066fba6cfbf4572786b071bbaea1139c2eab5a7155b635e48318d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string120 = "2e8ab836111066fba6cfbf4572786b071bbaea1139c2eab5a7155b635e48318d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string121 = "2fbf1231cc622fd4b910a7fc7b474af1dcd1acbdc13b8233b852416009b9bb20" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string122 = "2fbf1231cc622fd4b910a7fc7b474af1dcd1acbdc13b8233b852416009b9bb20" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string123 = "2ff4c6949bab3ffb8c95b21f9c5eb597b93af66e3bfb635ba2bf92fd534e995b" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string124 = "2ff4c6949bab3ffb8c95b21f9c5eb597b93af66e3bfb635ba2bf92fd534e995b" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string125 = "3130a3c87196583390827cf55f5e5e4ef008251885f1c9a07866df3699faab3d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string126 = "3130a3c87196583390827cf55f5e5e4ef008251885f1c9a07866df3699faab3d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string127 = "34fbf688da05fa13e0b3f8d18ae5aab81ce3865eb98908b236b8c593007adb5b" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string128 = "34fbf688da05fa13e0b3f8d18ae5aab81ce3865eb98908b236b8c593007adb5b" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string129 = "37c719615f3d72d457564a3f2af7669fbea6d651b92de213699419a4e8ac27e9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string130 = "37c719615f3d72d457564a3f2af7669fbea6d651b92de213699419a4e8ac27e9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string131 = "38bbfb8a6e3de5fb329505605290d408b8d99be65f351daf4b015773525a20e3" nocase ascii wide
        // Description: Mimikatz compiled hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string132 = "3929a5cf7450e6cd0efada336cf89f7a188f0d40e7f4a7a2bff91fd7a30c48b3" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string133 = "3d0e06086768500a2bf680ffbed0409d24b355887169b821d55233529ad2c62a" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string134 = "3d0e06086768500a2bf680ffbed0409d24b355887169b821d55233529ad2c62a" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string135 = "3e3956052088b12e9fca1e9a209c00e8e60f5bba79bc09881316c83758a93c1d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string136 = "3e3956052088b12e9fca1e9a209c00e8e60f5bba79bc09881316c83758a93c1d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string137 = "3e9a7fc50639f2077028d5cfd6ffeba037d03608f30af50cafc12a43d0a4a5e2" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string138 = "3e9a7fc50639f2077028d5cfd6ffeba037d03608f30af50cafc12a43d0a4a5e2" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string139 = "454711d2a1a5526d75e2df5ba08bd0a1a1e5833efc59bbe6b41e31b7c32e8e76" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string140 = "478e0f90d2d51a17f5ffce9dda75339848ef2bd5b8109b6695104a9ae8b71bc1" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string141 = "4802db51ec51c17bea27c97d871a840211f6d74b88eb9494b00b99a28957142a" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string142 = "48213dd6196f88e665f7ca5d9e139f56f9c54921ae9703a329f76b08ec364d3d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string143 = "48213dd6196f88e665f7ca5d9e139f56f9c54921ae9703a329f76b08ec364d3d" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string144 = "4ec058080435d27714e38d5544dacafdf3c7739dc3a0615a57cede8c124a9ae4" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string145 = "4ff7578df7293e50c9bdd48657a6ba0c60e1f6d06a2dd334f605af34fe6f75a5" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string146 = "4ff7578df7293e50c9bdd48657a6ba0c60e1f6d06a2dd334f605af34fe6f75a5" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string147 = "508764b5a7645ca6cd2968f9ad4a37029a7fe1f45d90b46b2f6c03393f5e2730" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string148 = "5191200b2b3d20b4e970acc72cca38d318ca463a88230580a426975a6f73bb49" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string149 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string150 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string151 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string152 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string153 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string154 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string155 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string156 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string157 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string158 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string159 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string160 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string161 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string162 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string163 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string164 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string165 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string166 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string167 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string168 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string169 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string170 = "51d45e6c5df6b43b17afc863794f34000d32fb37cd7c3664efc5bd99039ac3df" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string171 = "5475aa1a750cc743c15ce710fb14490b8a59a278c63b0e049954900eedd9df71" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string172 = "5475aa1a750cc743c15ce710fb14490b8a59a278c63b0e049954900eedd9df71" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string173 = "56c9dd7fe7e9f3e8692fe8e305214cfa2db85424b254f95c97e56e4b35193634" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string174 = "56c9dd7fe7e9f3e8692fe8e305214cfa2db85424b254f95c97e56e4b35193634" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string175 = "592357cfeb7bbc10865d9e64e4b778bd742a6abb452166e9f9b1eef404f67a31" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string176 = "592357cfeb7bbc10865d9e64e4b778bd742a6abb452166e9f9b1eef404f67a31" nocase ascii wide
        // Description: mimikatz GUID project
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string177 = "60D02E32-1711-4D9E-9AC2-10627C52EB40" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string178 = "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string179 = "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string180 = "620d4c08d472520f16e52e35c1eb622c43fe583b40b977b258828ac05f439dba" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string181 = "620d4c08d472520f16e52e35c1eb622c43fe583b40b977b258828ac05f439dba" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string182 = "62a32ce26d8954a32e41cb222e6c2fab2e25b3b99d7567a051a3875a0d5ee7e3" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string183 = "62a32ce26d8954a32e41cb222e6c2fab2e25b3b99d7567a051a3875a0d5ee7e3" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string184 = "66928c3316a12091995198710e0c537430dacefac1dbe78f12a331e1520142bd" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string185 = "66928c3316a12091995198710e0c537430dacefac1dbe78f12a331e1520142bd" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string186 = "6a4345d4d5465097dfbe8ba3d2007c7200c8cf320f9123abc1bf03f12dbe6b4d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string187 = "6a4345d4d5465097dfbe8ba3d2007c7200c8cf320f9123abc1bf03f12dbe6b4d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string188 = "6b8453724d41251986a3dc94f0e725d07a4c1b9171228e89ee8ef0daef3b0b2c" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string189 = "6b8453724d41251986a3dc94f0e725d07a4c1b9171228e89ee8ef0daef3b0b2c" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string190 = "6d955490b7ccb6ef77222ec41f494c186050fd9b6b022451ab8ec48104d79673" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string191 = "6fd569e4c0b8bb63b28317f10ca965d4921b126f601ce72824e40f71465b03ba" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string192 = "6fd569e4c0b8bb63b28317f10ca965d4921b126f601ce72824e40f71465b03ba" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string193 = "70c62e0f2725a158d53c4fe2be205bb5ae07264a85af693741761e7fb7c8c521" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string194 = "70c62e0f2725a158d53c4fe2be205bb5ae07264a85af693741761e7fb7c8c521" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string195 = "7409b573c0e8e5ab73e6e3fafbe635438fbfd6f2acb57a31c859f43ad623f64f" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string196 = "7409b573c0e8e5ab73e6e3fafbe635438fbfd6f2acb57a31c859f43ad623f64f" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string197 = "77cfad99621ef6951ec4809a6641e2d7623238b66afa3f6e993703eeff161da6" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string198 = "77cfad99621ef6951ec4809a6641e2d7623238b66afa3f6e993703eeff161da6" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string199 = "7a3a00796caebdd1e5d80cc330ea232e62fecefc264492892c3ff93f15c977a2" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string200 = "7a3a00796caebdd1e5d80cc330ea232e62fecefc264492892c3ff93f15c977a2" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string201 = "7accd179e8a6b2fc907e7e8d087c52a7f48084852724b03d25bebcada1acbca5" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string202 = "81027e82ed224ca43c939b8df5f99bf13e9d2191b177ae4d339075930ab2bb5b" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string203 = "81027e82ed224ca43c939b8df5f99bf13e9d2191b177ae4d339075930ab2bb5b" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string204 = "81a235c1c9cdb34c44f468239bd06a590a54cc4fcd624c676200097b45d55165" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string205 = "81a235c1c9cdb34c44f468239bd06a590a54cc4fcd624c676200097b45d55165" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string206 = "82e7270fab0c067f74ca4c8c8d0228ad49cb16149ea036ff6ec4a4fa62088c76" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string207 = "82e7270fab0c067f74ca4c8c8d0228ad49cb16149ea036ff6ec4a4fa62088c76" nocase ascii wide
        // Description: mimikatz GUID project
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string208 = "86FF6D04-208C-442F-B27C-E4255DD39402" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string209 = "8aec1bef3b7e7e8d8adcf79bdc1d0efcd6eaa94c2fa22e42dd1b21ecc49333cd" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string210 = "8aec1bef3b7e7e8d8adcf79bdc1d0efcd6eaa94c2fa22e42dd1b21ecc49333cd" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string211 = "8aec1bef3b7e7e8d8adcf79bdc1d0efcd6eaa94c2fa22e42dd1b21ecc49333cd" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string212 = "8aec1bef3b7e7e8d8adcf79bdc1d0efcd6eaa94c2fa22e42dd1b21ecc49333cd" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string213 = "8c18fe10b673b128e86bb6f1b6dd34eae23c4428ec66e8496d94fd04cfc17784" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string214 = "8c18fe10b673b128e86bb6f1b6dd34eae23c4428ec66e8496d94fd04cfc17784" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string215 = "8c97b09ebb432e60c9aef665c6db2be79a6439f1c59f683f36568f0bddda0c38" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string216 = "8c97b09ebb432e60c9aef665c6db2be79a6439f1c59f683f36568f0bddda0c38" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string217 = "8e0a61ae75c32370711ca475269fb91dfeb09534a1da08a4f3f1e71c13c1eaa9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string218 = "90c6e84dbeb83eef349d9ac17b1e005c12f42d74cea94a6c0f16a999792ac3f9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string219 = "90c6e84dbeb83eef349d9ac17b1e005c12f42d74cea94a6c0f16a999792ac3f9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string220 = "912018ab3c6b16b39ee84f17745ff0c80a33cee241013ec35d0281e40c0658d9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string221 = "912018ab3c6b16b39ee84f17745ff0c80a33cee241013ec35d0281e40c0658d9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string222 = "912ddcb057ae0b41311be77a00ad2952ab1521c12fc712284a4fbfb58f1105be" nocase ascii wide
        // Description: mimikatz UUID
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string223 = "921BB3E1-15EE-4bbe-83D4-C4CE176A481B" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string224 = "923195967668d70c92c62877cb79a93afecc4eb5144ce6609503123617d55bf3" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string225 = "9295fa0ab820c08fcab5107558f6d7ad390ec6b4a8112d82e11a51dea28c1862" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string226 = "93ba29924f9e4124a73302d5ec2da5f7891922d9420cb0ca8649b6e7a9e59894" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string227 = "93ba29924f9e4124a73302d5ec2da5f7891922d9420cb0ca8649b6e7a9e59894" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string228 = "94795fd89366e01bd6ce6471ff27c3782e2e16377a848426cf0b2e6baee9449b" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string229 = "94795fd89366e01bd6ce6471ff27c3782e2e16377a848426cf0b2e6baee9449b" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string230 = "96632f716df30af567da00d3624e245d162d0a05ac4b4e7cbadf63f04ca8d3da" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string231 = "96632f716df30af567da00d3624e245d162d0a05ac4b4e7cbadf63f04ca8d3da" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string232 = "9842380cb6f04a1ba1d6d161b14999037cd66f7bbde2bd55bf89835e20a5cdae" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string233 = "9842380cb6f04a1ba1d6d161b14999037cd66f7bbde2bd55bf89835e20a5cdae" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string234 = "9ad6a5728ea235b3ed9522a352a6f39fa92d3ac2b5bfebc6fae66638deb76b49" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string235 = "9ad6a5728ea235b3ed9522a352a6f39fa92d3ac2b5bfebc6fae66638deb76b49" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string236 = "9b4c1be9061e211f2133b67de7e5e51eb6ecf3f035f917a52137395bcbb8bf2e" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string237 = "9b4c1be9061e211f2133b67de7e5e51eb6ecf3f035f917a52137395bcbb8bf2e" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string238 = "9e49c482faf12eaefc62f5724c083e35de138b15d2c593db2398577ebd6fdf33" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string239 = "9e49c482faf12eaefc62f5724c083e35de138b15d2c593db2398577ebd6fdf33" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string240 = "9f7bb583f87b8cfc56d4319cdcfeb865c0db77a0f2110f87d5c694c7f7a0e514" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string241 = "9f7bb583f87b8cfc56d4319cdcfeb865c0db77a0f2110f87d5c694c7f7a0e514" nocase ascii wide
        // Description: mimikatz default strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string242 = /A\sLa\sVie.{0,1000}\sA\sL\'Amour/ nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string243 = "a0010bd12872028ba8a53276313527f7a332a23d4cdd0caed1060a45916e8cb4" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string244 = "a0010bd12872028ba8a53276313527f7a332a23d4cdd0caed1060a45916e8cb4" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string245 = "a12e94a01c3d1cee2942d15b20d30b9574eb23418b20563c134565ead57ed96f" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string246 = "a12e94a01c3d1cee2942d15b20d30b9574eb23418b20563c134565ead57ed96f" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string247 = "a2a8f773388c06df995500e1d74e8855b11771b21474af4efad67362cc32119e" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string248 = "a2a8f773388c06df995500e1d74e8855b11771b21474af4efad67362cc32119e" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string249 = "a3ededd9d0451b04eee2d9160448739af710bd5f380322e0b5992e9b64e1e3a5" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string250 = "a3ededd9d0451b04eee2d9160448739af710bd5f380322e0b5992e9b64e1e3a5" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string251 = "a65b022127a9e19bdb6e119e020cf70a89c4d59a156b8040d74a8f489dc490c2" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string252 = "a65b022127a9e19bdb6e119e020cf70a89c4d59a156b8040d74a8f489dc490c2" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string253 = "a814e455a709e0ee42fdec62b57f9a62cc3af6d31b2f54ff9d869a6736ded903" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string254 = "a814e455a709e0ee42fdec62b57f9a62cc3af6d31b2f54ff9d869a6736ded903" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string255 = "a92acb50dd8f358f4b2fb99a6f50332006c7823712acd62b88cadfe01c517d9b" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string256 = "a92acb50dd8f358f4b2fb99a6f50332006c7823712acd62b88cadfe01c517d9b" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string257 = "a98576591e0e03e13239e35f8e02e30b71b6e4109f568a3d245af6ac67591699" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string258 = "a98576591e0e03e13239e35f8e02e30b71b6e4109f568a3d245af6ac67591699" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string259 = "aafdc7daa6d0f982d64819a332aebc9576b166c78c38a16b065274e8c5dc518e" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string260 = "aafdc7daa6d0f982d64819a332aebc9576b166c78c38a16b065274e8c5dc518e" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string261 = "aef6ce3014add838cf676b57957d630cd2bb15b0c9193cf349bcffecddbc3623" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string262 = "aef6ce3014add838cf676b57957d630cd2bb15b0c9193cf349bcffecddbc3623" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string263 = "b016e0fb93032d4ab6f2fb2ec6388e3117442d836bed2fe38ae8b73d7b825c5e" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string264 = "b016e0fb93032d4ab6f2fb2ec6388e3117442d836bed2fe38ae8b73d7b825c5e" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string265 = "b095b574cadcf9fc517eedd434df402bdbf680f19ebe0c1298dd8f0818dfe5e8" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string266 = "b2790bce687c664f57f7dc0c08ac27488506fd510bdf4cc20d87d03a22270c0f" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string267 = "b2790bce687c664f57f7dc0c08ac27488506fd510bdf4cc20d87d03a22270c0f" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string268 = "b3639781bbed6842e8168ad211da8d0d3ba32d47152c2bc2e57f056665232ddd" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string269 = "b4dba70d556511c9a7dbf152960bd1e72c9149142f694f87d2d53b63d61a0803" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string270 = "b4dba70d556511c9a7dbf152960bd1e72c9149142f694f87d2d53b63d61a0803" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string271 = "bad19a193019cf92068c5cc4f95906a4e54744349ba8e303e6aee4324e95002d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string272 = "bee3d0ac0967389571ea8e3a8c0502306b3dbf009e8155f00a2829417ac079fc" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string273 = "bee3d0ac0967389571ea8e3a8c0502306b3dbf009e8155f00a2829417ac079fc" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string274 = "bee3d0ac0967389571ea8e3a8c0502306b3dbf009e8155f00a2829417ac079fc" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string275 = "bee3d0ac0967389571ea8e3a8c0502306b3dbf009e8155f00a2829417ac079fc" nocase ascii wide
        // Description: mimikatz default strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string276 = /benjamin\@gentilkiwi\.com/ nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string277 = "bfa29dd2bd1a62ce4133eca34faa6f46005557eea07f3bf5c8b4afce8006160d" nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string278 = "Build with love for POC only" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string279 = "c2635225a206bbd00ab89ef7e8418acdee38e2f2969be43c9d04031f3fbb0e14" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string280 = "c2635225a206bbd00ab89ef7e8418acdee38e2f2969be43c9d04031f3fbb0e14" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string281 = "c5cb049d25fab0401c450f94a536898884681ee07c56b485ba4c6066b1dae710" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string282 = "c5cb049d25fab0401c450f94a536898884681ee07c56b485ba4c6066b1dae710" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string283 = "c6093c8bbb01042db340ac8e538e4dd0e6074541d33281ce1c4dd256073601e6" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string284 = "c86c8e44048907b077f48cfb1d2de1eee216ff699e3a6ce240b6d107b7a6f128" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string285 = "c86c8e44048907b077f48cfb1d2de1eee216ff699e3a6ce240b6d107b7a6f128" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string286 = "cc585d962904351ce1d92195b0fc79034dc3b13144f7c7ff24cd9f768b25e9ef" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string287 = "cc585d962904351ce1d92195b0fc79034dc3b13144f7c7ff24cd9f768b25e9ef" nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string288 = /chocolate\.kirbi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string289 = /Copyright\s\(c\)\s2007\s\-\s2021\sgentilkiwi\s\(Benjamin\sDELPY\)/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string290 = "crypto::capi" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string291 = "crypto::certificates" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string292 = "crypto::certtohw" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string293 = "crypto::cng" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string294 = "crypto::extract" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string295 = "crypto::keys" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string296 = "crypto::providers" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string297 = "crypto::sc" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string298 = "crypto::scauth" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string299 = "crypto::tpminfo" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string300 = "d14447f41d11e0ed192d9161a60cee139fe8b01d921bbdff56abc01a5a653161" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string301 = "d14447f41d11e0ed192d9161a60cee139fe8b01d921bbdff56abc01a5a653161" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string302 = "d30f51bfd62695df96ba94cde14a7fae466b29ef45252c6ad19d57b4a87ff44e" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string303 = "d30f51bfd62695df96ba94cde14a7fae466b29ef45252c6ad19d57b4a87ff44e" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string304 = "d6521cf735fc2bb7f7c308b488c869d7cf4136c97b08cf0219ca2d6e64134290" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string305 = "d6521cf735fc2bb7f7c308b488c869d7cf4136c97b08cf0219ca2d6e64134290" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string306 = "d94e140fdb653c7fbfbc293a5f5ec37b012470dc4c2767b0040daf54aafb47f9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string307 = "d94e140fdb653c7fbfbc293a5f5ec37b012470dc4c2767b0040daf54aafb47f9" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string308 = "d9770865ea739a8f1702a2651538f4f4de2d92888d188d8ace2c79936f9c2688" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string309 = "d9770865ea739a8f1702a2651538f4f4de2d92888d188d8ace2c79936f9c2688" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string310 = "db385ea6858db4b4cb49897df9ec6d5cc4675aaf675e692466b3b50218e0eeca" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string311 = "db385ea6858db4b4cb49897df9ec6d5cc4675aaf675e692466b3b50218e0eeca" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string312 = "dc8e495f3d1ee0060009f69bcdc8b60265879d41d20dd0367a638a101d3a19c6" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string313 = "dc8e495f3d1ee0060009f69bcdc8b60265879d41d20dd0367a638a101d3a19c6" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string314 = "dd3f2e3349c378e1a415c4a6ad450cd3ae4ea29f3fe15d0a72bff64a44e1362a" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string315 = "dd3f2e3349c378e1a415c4a6ad450cd3ae4ea29f3fe15d0a72bff64a44e1362a" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string316 = "dpapi::blob" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string317 = "dpapi::cache" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string318 = "dpapi::capi" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string319 = "dpapi::chrome" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string320 = "dpapi::cloudapkd" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string321 = "dpapi::cloudapreg" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string322 = "dpapi::cng" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string323 = "dpapi::create" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string324 = "dpapi::cred" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string325 = "dpapi::credhist" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string326 = "dpapi::luna" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string327 = "dpapi::masterkey" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string328 = "dpapi::protect" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string329 = "dpapi::ps" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string330 = "dpapi::rdg" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string331 = "dpapi::sccm" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string332 = "dpapi::ssh" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string333 = "dpapi::tpm" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string334 = "dpapi::vault" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string335 = "dpapi::wifi" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string336 = "dpapi::wwman" nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 script argument
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string337 = "-DumpCreds" nocase ascii wide
        // Description: mimikatz GUID project
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string338 = "E049487C-C5BD-471E-99AE-C756E70B6520" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string339 = "e60c210687e79347d06f9a144ee84417ba9ac4c1f303720f2fe4509734d670d6" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string340 = "e60c210687e79347d06f9a144ee84417ba9ac4c1f303720f2fe4509734d670d6" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string341 = "e6b9b81643f27334434561f226d95e6729518eb4eb016e5a54a809fab583ef4d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string342 = "e6b9b81643f27334434561f226d95e6729518eb4eb016e5a54a809fab583ef4d" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string343 = "e81a8f8ad804c4d83869d7806a303ff04f31cce376c5df8aada2e9db2c1eeb98" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string344 = "e81a8f8ad804c4d83869d7806a303ff04f31cce376c5df8aada2e9db2c1eeb98" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string345 = "eda5a3b5c4316ec711ae975cdf6a483e244ac195e06254a0e9bade484d9c0533" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string346 = "eda5a3b5c4316ec711ae975cdf6a483e244ac195e06254a0e9bade484d9c0533" nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string347 = "Enable-SeDebugPrivilege" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string348 = /eo\.oe\.kiwi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string349 = "event::drop" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string350 = "f2c7d2d0539d1549c8f1a9a461b467d6ef0d4eb40c3ab8ba5412398d65a6f398" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string351 = "f2c7d2d0539d1549c8f1a9a461b467d6ef0d4eb40c3ab8ba5412398d65a6f398" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string352 = "f44118e8d6e227dea16f78d905178cf64ef019a5145aebc06d04d41ea5fc6482" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string353 = "fadfbd1210e864f660aabfc5cb6ae807721ae2d54df0e328d13bc62bcec66e6f" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string354 = "fadfbd1210e864f660aabfc5cb6ae807721ae2d54df0e328d13bc62bcec66e6f" nocase ascii wide
        // Description: mimikatz GUID project
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string355 = "FB9B5E61-7C34-4280-A211-E979E1D6977F" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string356 = "fc77b7dc19250416baf67ae9f87e85ebad700032b0d437c0bc2176b2585fca95" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string357 = "fc77b7dc19250416baf67ae9f87e85ebad700032b0d437c0bc2176b2585fca95" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string358 = "fe5fc5bfd15a4c3dbf5d057bcf109d4f4d1b8835085acca6c13508e7baf074a3" nocase ascii wide
        // Description: mimikatz archives hashes
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string359 = "fe5fc5bfd15a4c3dbf5d057bcf109d4f4d1b8835085acca6c13508e7baf074a3" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string360 = /gentilkiwi\s\(Benjamin\sDELPY\)/ nocase ascii wide
        // Description: author of mimikatz and multiple other windows exploitation tools
        // Reference: https://github.com/gentilkiwi/
        $string361 = "gentilkiwi" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string362 = "Hello from DCShadow" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string363 = /http\:\/\/blog\.gentilkiwi\.com\/mimikatz/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string364 = "id::modify" nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string365 = "Import-DllInRemoteProcess" nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string366 = "Invoke-CreateRemoteThread" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/g4uss47/Invoke-Mimikatz
        $string367 = "Invoke-Mimikatz" nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string368 = "Invoke-Mimikatz" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/g4uss47/Invoke-Mimikatz
        $string369 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: PowerShell Scripts focused on Post-Exploitation Capabilities
        // Reference: https://github.com/xorrior/RandomPS-Scripts
        $string370 = "Invoke-RemoteMimikatz" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/g4uss47/Invoke-Mimikatz
        $string371 = /Invoke\-UpdateMimikatzScript\.ps1/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string372 = "kerberos::ask" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string373 = "kerberos::clist" nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string374 = "kerberos::golden" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string375 = "kerberos::golden" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string376 = "kerberos::hash" nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string377 = "kerberos::list" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. This function lists all Kerberos tickets in memory
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string378 = "kerberos::list" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string379 = "kerberos::ptc" nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string380 = "kerberos::ptt" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string381 = "kerberos::ptt" nocase ascii wide
        // Description: Mimikatz Unconstrained delegation. With administrative privileges on a server with Unconstrained Delegation set we can dump the TGTs for other users that have a connection. If we do this successfully. we can impersonate the victim user towards any service in the domain.
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string382 = /kerberos\:\:ptt.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string383 = "kerberos::purge" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string384 = "kerberos::tgt" nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string385 = "KiRBi ticket for mimikatz" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string386 = "kiwi flavor !" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string387 = "Kiwi Legit Printer" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string388 = "Kiwi Security Support Provider" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string389 = "KIWI_MSV1_0_PRIMARY_CREDENTIALS KO" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string390 = "kuhl_m_lsadump_getComputerAndSyskey" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string391 = "kuhl_m_lsadump_getUsersAndSamKey" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string392 = /kuhl_m_sekurlsa_nt6\.c/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string393 = /kuhl_m_sekurlsa_nt6\.h/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string394 = /kuhl_m_sekurlsa_packages\.c/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string395 = /kuhl_m_sekurlsa_packages\.h/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string396 = /kuhl_m_sekurlsa_utils\.c/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string397 = /kuhl_m_sekurlsa_utils\.h/ nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string398 = "Lecture KIWI_MSV1_0_" nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string399 = /LSA\sdump\sprograme\s\(bootkey\/syskey\)\s\-\spwdump\sand\sothers/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string400 = "lsadump::" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string401 = "lsadump::backupkeys" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string402 = "lsadump::cache" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string403 = "lsadump::changentlm" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string404 = "lsadump::dcshadow" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string405 = "lsadump::dcsyn" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string406 = "lsadump::dcsync" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string407 = "lsadump::lsa" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string408 = "lsadump::mbc" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string409 = "lsadump::netsync" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string410 = "lsadump::packages" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string411 = "lsadump::postzerologon" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string412 = "lsadump::RpData" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string413 = "lsadump::sam" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string414 = "lsadump::secrets" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string415 = "lsadump::setntlm" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string416 = "lsadump::trust" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string417 = "lsadump::zerologon" nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string418 = "LSASS minidump file for " nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string419 = /mimi32\.exe\s/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string420 = /mimi64\.exe\s/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string421 = /mimidrv\s\(mimikatz\)/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string422 = "mimidrv" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string423 = /mimidrv\.pdb/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string424 = /mimidrv\.sys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string425 = /mimidrv\.sys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string426 = /mimidrv\.sys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string427 = /mimidrv\.zip/ nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string428 = /mimikatz\s2\.2\.0\sx64/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string429 = "mimikatz for Windows" nocase ascii wide
        // Description: Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets.
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string430 = "Mimikatz" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string431 = /mimikatz\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string432 = "mimikatz_trunk" nocase ascii wide
        // Description: mimikatz archive names
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string433 = /mimikatz_trunk\.7z/ nocase ascii wide
        // Description: mimikatz archive names
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string434 = /mimikatz_trunk\.zip/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string435 = "mimikatzsvc" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string436 = /mimilib\s\(mimikatz\)/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string437 = /mimilib\s\(mimikatz\)/ nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string438 = /mimilib\sfor\sWindows\s\(mimikatz\)/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string439 = /mimilib\sfor\sWindows\s\(mimikatz\)/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string440 = "mimilib" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string441 = /mimilib\.dll/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string442 = /mimilib\.dll/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string443 = "mimilove" nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string444 = /mimilove\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string445 = /mimilove\.vcxproj/ nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string446 = "mimilove_kerberos" nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string447 = "mimilove_lsasrv" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string448 = /mimispool\s\(mimikatz\)/ nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string449 = /mimispool\sfor\sWindows\s\(mimikatz\)/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string450 = /mimispool\.dll/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string451 = "misc::aadcookie" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string452 = "misc::clip" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string453 = "misc::cmd" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string454 = "misc::compress" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string455 = "misc::detours" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string456 = "misc::efs" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string457 = "misc::lock" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string458 = "misc::memssp" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string459 = "misc::mflt" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string460 = "misc::ncroutemon" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string461 = "misc::ngcsign" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string462 = "misc::printnightmare" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string463 = "misc::regedit" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string464 = "misc::sccm" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string465 = "misc::shadowcopies" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string466 = "misc::skeleton" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string467 = "misc::spooler" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string468 = "misc::taskmgr" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string469 = "misc::wp" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string470 = "misc::xor" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string471 = "net::alias" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string472 = "net::deleg" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string473 = "net::group" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string474 = "net::if" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string475 = "net::serverinfo" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string476 = "net::session" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string477 = "net::share" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string478 = "net::stats" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string479 = "net::tod" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string480 = "net::trust" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string481 = "net::user" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string482 = "net::wsession" nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string483 = /pingcastle\.com.{0,1000}mysmartlogon\.com/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/Stealthbits/poshkatz
        $string484 = /poshkatz\.psd1/ nocase ascii wide
        // Description: Mimikatz keywords
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string485 = /powerkatz\.dll/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string486 = "privilege::backup" nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string487 = "privilege::debug" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string488 = "privilege::debug" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string489 = "privilege::driver" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string490 = "privilege::id" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string491 = "privilege::name" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string492 = "privilege::restore" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string493 = "privilege::security" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string494 = "privilege::sysenv" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string495 = "privilege::tcb" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string496 = "process::exports" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string497 = "process::suspend" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/skelsec/pypykatz
        $string498 = "pypykatz lsa minidump" nocase ascii wide
        // Description: invoke mimiaktz string found used by the tool EDRaser 
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string499 = "QWRkLU1lbWJlciBOb3RlUHJvcGVydHkgLU5hbWUgVmlydHVhbFByb3RlY3QgLVZhbHVlICRWaXJ0dWFsUHJvdGVjdA" nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string500 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PackagePointAndPrint\\"\s\/f\s\/v\sPackagePointAndPrintOnly\s\/t\sREG_DWORD\s\/d\s1/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string501 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PackagePointAndPrint\\"\s\/f\s\/v\sPackagePointAndPrintServerList\s\/t\sREG_DWORD\s\/d\s1/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string502 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PackagePointAndPrint\\ListofServers\\"\s\/f\s\/v\s1\s\/t\sREG_SZ\s\/d\s/ nocase ascii wide
        // Description: mimikatz command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string503 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sNT\\Printers\\PointAndPrint\\"\s\/f\s\/v\sRestrictDriverInstallationToAdministrators\s\/t\sREG_DWORD\s\/d\s0/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string504 = "rpc::enum" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string505 = "rpc::server" nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string506 = "sekurlsa " nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string507 = "sekurlsa::backupkeys" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string508 = "sekurlsa::bootkey" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string509 = "sekurlsa::cloudap" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string510 = "sekurlsa::credman" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string511 = "sekurlsa::dpapi" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string512 = "sekurlsa::dpapisystem" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. This function dumps DPAPI backup keys for users who have logged on to the system
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string513 = "sekurlsa::ekeys" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string514 = "sekurlsa::kerberos" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string515 = "sekurlsa::krbtgt" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string516 = "sekurlsa::livessp" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. This function retrieves plaintext credentials from the LSA secrets in memory.
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string517 = "sekurlsa::logonpasswords" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string518 = "sekurlsa::minidump" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string519 = "sekurlsa::msv" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string520 = "sekurlsa::process" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash.This function performs pass-the-hash attacks allowing an attacker to authenticate to a remote system with a stolen hash.
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string521 = "sekurlsa::pth" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string522 = "sekurlsa::ssp" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string523 = "sekurlsa::tickets" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string524 = "sekurlsa::trust" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string525 = "sekurlsa::tspkg" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string526 = "sekurlsa::wdigest" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string527 = "service::preshutdown" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string528 = "sid::clear" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string529 = "sid::lookup" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string530 = "sid::modify" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string531 = "sid::patch" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string532 = "standard::answer" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string533 = "standard::base64" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string534 = "standard::cd" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string535 = "standard::cls" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string536 = "standard::coffee" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string537 = "standard::exit" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string538 = "standard::hostname" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string539 = "standard::localtime" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string540 = "standard::log" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string541 = "standard::sleep" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string542 = "standard::version" nocase ascii wide
        // Description: Mimikatz Unconstrained delegation. With administrative privileges on a server with Unconstrained Delegation set we can dump the TGTs for other users that have a connection. If we do this successfully. we can impersonate the victim user towards any service in the domain.
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string543 = /ticket\.kirbi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string544 = "token::elevate" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string545 = "token::whoami" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string546 = "ts::logonpasswords" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string547 = "ts::mstsc" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string548 = "ts::multirdp" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string549 = "ts::remote" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string550 = "ts::sessions" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string551 = "vault::cred" nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string552 = /vincent\.letoux\@gmail\.com/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/vyrus001/go-mimikatz
        $string553 = "vyrus001/go-mimikatz" nocase ascii wide
        // Description: mimikatz exploitation default password
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string554 = "waza1234" nocase ascii wide
        // Description: mimikatz strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string555 = "Waza1234/Waza1234/Waza1234/" nocase ascii wide

    condition:
        any of them
}
