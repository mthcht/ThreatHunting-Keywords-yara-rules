rule merlin
{
    meta:
        description = "Detection patterns for the tool 'merlin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string1 = /\sAdd\-RemoteRegBackdoor\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string2 = /\sConfigure\-Victim\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string3 = /\sCreate\-HotKeyLNK\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string4 = /\sdump\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string5 = /\sdumpCredStore\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string6 = /\sGet\-GPPPassword\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string7 = /\sGet\-InfectedThread\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string8 = /\sGet\-InjectedThread\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string9 = /\sGet\-OSTokenInformation\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string10 = /\sGet\-ScheduledTaskComHandler\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string11 = /\sGet\-TGSCipher\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string12 = /\sHostEnum\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string13 = /\sInveigh\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string14 = /\sInvoke\-ADSBackdoor\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string15 = /\sInvoke\-DCOM\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string16 = /\sInvoke\-DCOMPowerPointPivot\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string17 = /\sInvoke\-ExcelMacroPivot\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string18 = /\sInvoke\-InternalMonologue\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string19 = /\sInvoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string20 = /\sInvoke\-PowerThIEf\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string21 = /\sInvoke\-WMILM\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string22 = /\sletmein\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string23 = /\sOut\-Minidump\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string24 = /\sPotentiallyCrackableAccounts\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string25 = /\sPowerUp\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string26 = /\spsgetsys\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string27 = /\sRemoteAccessPolicyEnumeration\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string28 = /\sRemoteHashRetrieval\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string29 = /\sSeatBelt\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string30 = /\sSharpRoast\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string31 = /\sTater\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string32 = /\stoteslegit\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string33 = /\/Add\-RemoteRegBackdoor\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string34 = /\/Configure\-Victim\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string35 = /\/Create\-HotKeyLNK\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string36 = /\/decrypting\-lsa\-secrets\.html/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string37 = /\/dump\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string38 = /\/dumpCredStore\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string39 = /\/etc\/ld\.so\.preload\s\&\&\srm.{0,1000}\sprocess\ssuccessfully\shidden/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string40 = /\/evil_script\.py/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string41 = /\/Get\-GPPPassword\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string42 = /\/Get\-InfectedThread\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string43 = /\/Get\-InjectedThread\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string44 = /\/Get\-OSTokenInformation\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string45 = /\/Get\-ScheduledTaskComHandler\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string46 = /\/Get\-TGSCipher\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string47 = /\/HostEnum\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string48 = /\/Inveigh\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string49 = /\/Invoke\-ADSBackdoor\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string50 = /\/Invoke\-DCOM\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string51 = /\/Invoke\-DCOMPowerPointPivot\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string52 = /\/Invoke\-ExcelMacroPivot\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string53 = /\/Invoke\-InternalMonologue\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string54 = /\/Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string55 = /\/Invoke\-PowerThIEf\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string56 = /\/Invoke\-WMILM\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string57 = /\/letmein\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string58 = /\/merlin\.git/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string59 = /\/merlin\.html/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string60 = /\/merlin\/data\/modules\// nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string61 = /\/Out\-Minidump\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string62 = /\/pkg\/merlin\.go/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string63 = /\/PotentiallyCrackableAccounts\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string64 = /\/PowerUp\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string65 = /\/psgetsys\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string66 = /\/RemoteAccessPolicyEnumeration\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string67 = /\/RemoteHashRetrieval\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string68 = /\/SeatBelt\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string69 = /\/SharpRoast\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string70 = /\/Tater\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string71 = /\/toteslegit\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string72 = /\\\\\.\\pipe\\Merlin/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string73 = /\\Add\-RemoteRegBackdoor\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string74 = /\\Configure\-Server\.psm1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string75 = /\\Configure\-Victim\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string76 = /\\Configure\-Victim\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string77 = /\\Create\-HotKeyLNK\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string78 = /\\dump\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string79 = /\\dumpCredStore\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string80 = /\\evil_script\.py/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string81 = /\\Get\-GPPPassword\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string82 = /\\Get\-InfectedThread\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string83 = /\\Get\-InjectedThread\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string84 = /\\Get\-OSTokenInformation\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string85 = /\\Get\-ScheduledTaskComHandler\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string86 = /\\Get\-TGSCipher\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string87 = /\\HostEnum\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string88 = /\\Inveigh\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string89 = /\\Invoke\-ADSBackdoor\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string90 = /\\Invoke\-DCOM\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string91 = /\\Invoke\-DCOMPowerPointPivot\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string92 = /\\Invoke\-ExcelMacroPivot\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string93 = /\\Invoke\-InternalMonologue\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string94 = /\\Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string95 = /\\Invoke\-PowerThIEf\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string96 = /\\Invoke\-WMILM\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string97 = /\\letmein\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string98 = /\\merlin\\data\\modules\\/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string99 = /\\NiceFile\.ppam/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string100 = /\\Out\-Minidump\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string101 = /\\pkg\\merlin\.go/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string102 = /\\PotentiallyCrackableAccounts\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string103 = /\\PowerUp\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string104 = /\\psgetsys\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string105 = /\\RemoteAccessPolicyEnumeration\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string106 = /\\RemoteHashRetrieval\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string107 = /\\SeatBelt\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string108 = /\\SharpRoast\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string109 = /\\SharpRoast\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string110 = /\\Tater\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string111 = /\\toteslegit\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string112 = /Add\-RemoteRegBackdoor\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string113 = /B11F13DC6E6546E134FE8F836C13CCBBD1D8E5120FBD2B40A81E66DFD7C4EBC3/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string114 = /b691b9066d40a8d341e06f30cc7d94c3b1db62b3f49b5869c9b1e59828995550/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string115 = /Create\-HotKeyLNK\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string116 = /CrontabPersistence\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string117 = /df95ba5fe88d5031a4f5dfbfc8cecc64f6fd0cbbd4a9b9248666344987a9619f/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string118 = /Find\-BadPrivilege\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string119 = /Find\-BadPrivileges\-DomainComputers\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string120 = /Find\-ComputersWithRemoteAccessPolicies\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string121 = /Find\-ComputersWithRemoteAccessPolicies\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string122 = /Find\-PotentiallyCrackableAccounts\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string123 = /Get\-GPPPassword\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string124 = /Get\-RemoteLocalAccountHash\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string125 = /Get\-RemoteMachineAccountHash\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string126 = /Get\-ScheduledTaskComHandler\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string127 = /Invoke\-ADSBackdoor/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string128 = /Invoke\-ADSBackdoor\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string129 = /Invoke\-DCOMObjectScan\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string130 = /Invoke\-DCOMPowerPointPivot/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string131 = /Invoke\-ExcelMacroPivot/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string132 = /Invoke\-ExcelMacroPivot\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string133 = /Invoke\-ExecutionCommand\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string134 = /Invoke\-InternalMonologue/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string135 = /Invoke\-InternalMonologue\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string136 = /Invoke\-M\.i\.m\.i\.k\.a\.t\.z/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string137 = /Invoke\-Mimikatz/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string138 = /Invoke\-Mimikatz\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string139 = /Invoke\-PowerThIEf/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string140 = /Invoke\-PowerThIEf\.ps1/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string141 = /Invoke\-WMILM/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string142 = /Invoke\-WMILM\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string143 = /M\.i\.m\.i\.k\.a\.t\.z/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string144 = /Merlin_ServiceDesc\sis\sthe\sgrpc\.ServiceDesc\sfor\sMerlin\sservice/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string145 = /Merlin_v0\.1Beta\.zip/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string146 = /merlinAgent\-.{0,1000}\.7z/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string147 = /merlinAgent\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string148 = /merlinAgent\-Darwin\-/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string149 = /merlinAgent\-Linux\-/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string150 = /merlinServer\-.{0,1000}\.7z/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string151 = /merlinServer\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string152 = /merlinserver\.go/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string153 = /merlinserver_windows_x64\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string154 = /merlinServer\-Darwin\-x64\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string155 = /merlinServer\-Darwin\-x64\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string156 = /merlinServer\-Linux/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string157 = /merlinServer\-Linux\-x64\.7z/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string158 = /merlinServerLog\.txt/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string159 = /merlinServer\-Windows\-x64\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string160 = /merlinServer\-Windows\-x64\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string161 = /MimiPenguin\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string162 = /Ne0nd0g\/merlin/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string163 = /rpc\.Merlin\.Exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string164 = /rpc\.Merlin\.RunAs/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string165 = /russel\.vantuyl\@gmail\.com/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string166 = /SafetyKatz\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string167 = /shellcodeInjection\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string168 = /ShellProfilePersistence\.json/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string169 = /SPN\:SharpRoast\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin
        $string170 = /srv\.\(MerlinServer\)\.Exe/ nocase ascii wide

    condition:
        any of them
}
