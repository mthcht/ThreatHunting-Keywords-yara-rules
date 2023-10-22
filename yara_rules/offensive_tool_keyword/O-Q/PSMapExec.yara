rule PSMapExec
{
    meta:
        description = "Detection patterns for the tool 'PSMapExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSMapExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string1 = /\s\-\sRemoved\sdisabled\saccounts\sfrom\sspraying/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string2 = /\s\$KerbDump/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string3 = /\s\-Method\sGenRelayList/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string4 = /\s\-Method\sSessionHunter/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string5 = /\s\-Method\sSpray\s\-AccountAsPassword/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string6 = /\s\-Method\sSpray\s\-EmptyPassword/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string7 = /\s\-Method\sSpray\s\-Hash\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string8 = /\s\-Method\sSpray\s\-Password\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string9 = /\s\-Module\skerbdump/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string10 = /\s\-Name\s\"Test\.PME\"\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string11 = /\s\-notcontains\s.*\s\-notlike\s\"ntuser\.dat.*\"\s\-and\s\$_\.Extension\s\-ne\s\"\.tm/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string12 = /\s\-Targets\s.*\s\-Method\s.*\s\-LocalAuth/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string13 = /\s\-Targets\sAll\s\-Method\sWMI/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string14 = /\s\-Targets\sDCs/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string15 = /\swill\sbe\swritten\sto\sPME\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string16 = /\"Successful\sConnection\sPME\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string17 = /\$BaseTicket\s\|\sSelect\-String\s\-Pattern\s\'doI\./ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string18 = /\$FQDNDomainPlusAccountOperators/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string19 = /\$FQDNDomainPlusDomainAdmins/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string20 = /\$FQDNDomainPlusEnterpriseAdmins/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string21 = /\$FQDNDomainPlusServerOperators/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string22 = /\$MimiTickets/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string23 = /\$newClass\[\"__CLASS\"\]\s\=\s\"PMEClass\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string24 = /\/Kirby\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string25 = /\/PsMapExec\.git/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string26 = /\/PsMapExec\// nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string27 = /\[string\]\$Class\s\=\s\"PMEClass\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string28 = /\\\.eKeys\-Parsed\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string29 = /\\\\\$ComputerName\sdelete\s\$ServiceName/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string30 = /\\\\.*\screate\sService_.*\sbinpath\=\s`\"C:\\Windows\\System32\\cmd\.exe\s\/c\spowershell\.exe\s\-enc\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string31 = /\\Kirby\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string32 = /\\PME\\.*\-ConsoleHistory\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string33 = /\\PME\\Console\sHistory\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string34 = /\\PME\\eKeys\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string35 = /\\PME\\LogonPasswords/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string36 = /\\PME\\LSA\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string37 = /\\PME\\MSSQL\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string38 = /\\PME\\SAM\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string39 = /\\PME\\Sessions\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string40 = /\\PME\\SMB\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string41 = /\\PME\\Spraying\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string42 = /\\PME\\Tickets\\Kerbdump/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string43 = /\\PME\\Tickets\\MimiTickets/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string44 = /\\PME\\User\sFiles\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string45 = /\\PME\\VNC\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string46 = /\\SAM\\\.Sam\-Full\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string47 = /\\Sessions\\SH\-MatchedGroups\-.*\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string48 = /\\Test\.PME/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string49 = /\\Tickets\\KerbDump/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string50 = /\\VNC\\\.VNC\-Non\-Auth\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string51 = /\|IEX}DumpSAM/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string52 = /asktgt\s\/user.*\s\/domain:.*\s\/password:.*\s\/opsec\s\/force\s\/ptt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string53 = /Assembly\.GetType\(\"System\.Management\.Automation\.AmsiUtils\"\)\.getField\(\"amsiInitFailed\".*\'NonPublic.*Static\'\)\.SetValue\(\$null.*\$true\)/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string54 = /ComputerDirectory\\.*\.FullDump\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string55 = /Created\sdirectory\sfor\sPME\sat\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string56 = /dump\s\/service:krbtgt\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string57 = /earching\sfor\ssystems\swhere\sprivileged\susers\'\scredentials\smight\sbe\sin\srunning\smemory/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string58 = /eKeys\\.*\-eKeys\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string59 = /\-EmptyPassword\-Users\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string60 = /function\sDumpSAM/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string61 = /function\sGNLPH.*Get\-ItemProperty\s\"HKLM:SAM\\SAM\\Domains\\Account\\Users\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string62 = /Function\sPsMapExec/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string63 = /Get\-GroupMembers\s\-GroupName\s\"Account\sOperators\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string64 = /Get\-GroupMembers\s\-GroupName\s\"Domain\sAdmins\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string65 = /Get\-GroupMembers\s\-GroupName\s\"Enterprise\sAdmins\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string66 = /Get\-GroupMembers\s\-GroupName\s\"Server\sOperators\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string67 = /H4sIAAAAAAAEACVQ30vDMBB/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string68 = /H4sIAAAAAAAEANy9CZwcRfU43tPd093Tc/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string69 = /H4sIAAAAAAAEAOx9CVhTR9fw3CQkYScgqyAILsgm/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string70 = /https:\/\/github\.com\/The\-Viper\-One/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string71 = /https:\/\/viperone\.gitbook\.io\/pentest\-everything/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string72 = /IAS\s\-Process\s.*aad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string73 = /IAS\s\-Process\s{GNLPH}.*\$excludedUsernames\=\@\(\"Guest.*DefaultAccount.*WDAGUtilityAccount/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string74 = /InjectTicket.*ptt\s\/ticket:/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string75 = /Invoke\-Mongoose/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string76 = /Invoke\-Pandemonium\s\-Command/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string77 = /Invoke\-Pandemonium\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string78 = /Invoke\-Rubeus\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string79 = /Invoke\-Rubeus/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string80 = /Invoke\-SharpRDP/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string81 = /KerbDump\\.*\-Tickets\-KerbDump\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string82 = /LogonPasswords\\.*\-LogonPasswords\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string83 = /LogonPasswords\\\.AllUniqueNTLM\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string84 = /MimiTickets\\.*\-Tickets\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string85 = /New\-Object\sSystem\.Management\.ManagementClass\(\"\\\\\\\$env:computername\\root\\cimv2.*\[\"__CLASS\"\]\s\=\s\"PMEClass\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string86 = /PME\\LSA\\.*\-LSA\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string87 = /PME\\UserFiles\\.*\-UserFiles\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string88 = /PsMapExec\s\-/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string89 = /PsMapExec\swill\scontinue\sin\sthe\scurrent\susers\scontext/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string90 = /PsMapExec\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string91 = /PsMapExec\-main/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string92 = /SAM\\.*\-SAMHashes\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string93 = /SAM\\.*\-SAMHashes\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string94 = /SAM\\\.Sam\-Full\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string95 = /SMB\\SigningNotRequired\-.*\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string96 = /Specified\suser\sis\sa\sDomain\sAdmin\.\sUse\sthe\s\-Force\sswitch\sto\soverride/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string97 = /Specified\suser\sis\sa\sEnterprise\sAdmin\.\sUse\sthe\s\-Force\sswitch\sto\soverride/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string98 = /Spraying\sempty\spasswords/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string99 = /Spraying\susernames\sas\spasswords/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string100 = /Spraying\\.*\-AccountAsPassword\-Users\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string101 = /Spraying\\.*\-Password\-Users\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string102 = /Supply\seither\sa\s32\-character\sRC4\/NT\shash\sor\sa\s64\-character\sAES256\shash/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string103 = /tgtdeleg\s\/nowrap/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string104 = /The\-Viper\-One\/PME\-Scripts/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string105 = /The\-Viper\-One\/PsMapExec/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string106 = /to\s\$LogonPasswords/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string107 = /Unhandled\sRubeus\sexception:/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string108 = /VNC\-NoAuth\s\-ComputerName\s.*\s\-Port\s/ nocase ascii wide

    condition:
        any of them
}