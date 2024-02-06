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
        $string11 = /\s\-notcontains\s.{0,1000}\s\-notlike\s\"ntuser\.dat.{0,1000}\"\s\-and\s\$_\.Extension\s\-ne\s\"\.tm/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string12 = /\s\-Targets\s.{0,1000}\s\-Method\s.{0,1000}\s\-LocalAuth/ nocase ascii wide
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
        $string25 = /\/Kirby\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string26 = /\/PsMapExec\.git/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string27 = /\/PsMapExec\// nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string28 = /\[string\]\$Class\s\=\s\"PMEClass\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string29 = /\\\.eKeys\-Parsed\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string30 = /\\\\\$ComputerName\sdelete\s\$ServiceName/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string31 = /\\\\.{0,1000}\screate\sService_.{0,1000}\sbinpath\=\s\`\"C\:\\Windows\\System32\\cmd\.exe\s\/c\spowershell\.exe\s\-enc\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string32 = /\\Kirby\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string33 = /\\Kirby\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string34 = /\\PME\\.{0,1000}\-ConsoleHistory\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string35 = /\\PME\\Console\sHistory\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string36 = /\\PME\\eKeys\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string37 = /\\PME\\LogonPasswords/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string38 = /\\PME\\LSA\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string39 = /\\PME\\MSSQL\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string40 = /\\PME\\SAM\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string41 = /\\PME\\Sessions\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string42 = /\\PME\\SMB\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string43 = /\\PME\\Spraying\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string44 = /\\PME\\Tickets\\Kerbdump/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string45 = /\\PME\\Tickets\\MimiTickets/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string46 = /\\PME\\User\sFiles\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string47 = /\\PME\\VNC\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string48 = /\\SAM\\\.Sam\-Full\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string49 = /\\Sessions\\SH\-MatchedGroups\-.{0,1000}\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string50 = /\\Test\.PME/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string51 = /\\Tickets\\KerbDump/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string52 = /\\VNC\\\.VNC\-Non\-Auth\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string53 = /\|IEX\}DumpSAM/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string54 = /asktgt\s\/user.{0,1000}\s\/domain\:.{0,1000}\s\/password\:.{0,1000}\s\/opsec\s\/force\s\/ptt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string55 = /Assembly\.GetType\(\"System\.Management\.Automation\.AmsiUtils\"\)\.getField\(\"amsiInitFailed\".{0,1000}\'NonPublic.{0,1000}Static\'\)\.SetValue\(\$null.{0,1000}\$true\)/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string56 = /ComputerDirectory\\.{0,1000}\.FullDump\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string57 = /Created\sdirectory\sfor\sPME\sat\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string58 = /dump\s\/service\:krbtgt\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string59 = /DumpSAM\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string60 = /earching\sfor\ssystems\swhere\sprivileged\susers\'\scredentials\smight\sbe\sin\srunning\smemory/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string61 = /eKeys\\.{0,1000}\-eKeys\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string62 = /\-EmptyPassword\-Users\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string63 = /function\sDumpSAM/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string64 = /function\sGNLPH.{0,1000}Get\-ItemProperty\s\"HKLM\:SAM\\SAM\\Domains\\Account\\Users\\/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string65 = /Function\sPsMapExec/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string66 = /Get\-GroupMembers\s\-GroupName\s\"Account\sOperators\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string67 = /Get\-GroupMembers\s\-GroupName\s\"Domain\sAdmins\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string68 = /Get\-GroupMembers\s\-GroupName\s\"Enterprise\sAdmins\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string69 = /Get\-GroupMembers\s\-GroupName\s\"Server\sOperators\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string70 = /H4sIAAAAAAAEACVQ30vDMBB/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string71 = /H4sIAAAAAAAEANy9CZwcRfU43tPd093Tc/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string72 = /H4sIAAAAAAAEAOx9CVhTR9fw3CQkYScgqyAILsgm/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string73 = /https\:\/\/github\.com\/The\-Viper\-One/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string74 = /https\:\/\/viperone\.gitbook\.io\/pentest\-everything/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string75 = /IAS\s\-Process\s.{0,1000}aad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string76 = /IAS\s\-Process\s\{GNLPH\}.{0,1000}\$excludedUsernames\=\@\(\"Guest.{0,1000}DefaultAccount.{0,1000}WDAGUtilityAccount/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string77 = /InjectTicket.{0,1000}ptt\s\/ticket\:/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string78 = /Invoke\-Mongoose/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string79 = /Invoke\-MSSQLup/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string80 = /Invoke\-NETMongoose/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string81 = /Invoke\-NTDS\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string82 = /Invoke\-Pandemonium\s\-Command/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string83 = /Invoke\-Pandemonium\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string84 = /Invoke\-Rubeus\s/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string85 = /Invoke\-Rubeus/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string86 = /Invoke\-SecretsDump\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string87 = /Invoke\-SharpRDP/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string88 = /Invoke\-SharpRDPTest/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string89 = /KerbDump\\.{0,1000}\-Tickets\-KerbDump\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string90 = /LogonPasswords\\.{0,1000}\-LogonPasswords\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string91 = /LogonPasswords\\\.AllUniqueNTLM\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string92 = /MimiTickets\\.{0,1000}\-Tickets\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string93 = /New\-Object\sSystem\.Management\.ManagementClass\(\"\\\\\\\$env\:computername\\root\\cimv2.{0,1000}\[\"__CLASS\"\]\s\=\s\"PMEClass\"/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string94 = /PME\\LSA\\.{0,1000}\-LSA\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string95 = /PME\\UserFiles\\.{0,1000}\-UserFiles\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string96 = /PsMapExec\s\-/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string97 = /PsMapExec\swill\scontinue\sin\sthe\scurrent\susers\scontext/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string98 = /PsMapExec\.ps1/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string99 = /PsMapExec\-main/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string100 = /SAM\\.{0,1000}\-SAMHashes\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string101 = /SAM\\.{0,1000}\-SAMHashes\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string102 = /SAM\\\.Sam\-Full\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string103 = /SMB\\SigningNotRequired\-.{0,1000}\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string104 = /Specified\suser\sis\sa\sDomain\sAdmin\.\sUse\sthe\s\-Force\sswitch\sto\soverride/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string105 = /Specified\suser\sis\sa\sEnterprise\sAdmin\.\sUse\sthe\s\-Force\sswitch\sto\soverride/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string106 = /Spraying\sempty\spasswords/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string107 = /Spraying\susernames\sas\spasswords/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string108 = /Spraying\\.{0,1000}\-AccountAsPassword\-Users\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string109 = /Spraying\\.{0,1000}\-Password\-Users\.txt/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string110 = /Supply\seither\sa\s32\-character\sRC4\/NT\shash\sor\sa\s64\-character\sAES256\shash/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string111 = /tgtdeleg\s\/nowrap/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string112 = /The\-Viper\-One\/PME\-Scripts/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string113 = /The\-Viper\-One\/PsMapExec/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string114 = /to\s\$LogonPasswords/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string115 = /Unhandled\sRubeus\sexception\:/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string116 = /VNC\-NoAuth\s\-ComputerName\s.{0,1000}\s\-Port\s/ nocase ascii wide

    condition:
        any of them
}
