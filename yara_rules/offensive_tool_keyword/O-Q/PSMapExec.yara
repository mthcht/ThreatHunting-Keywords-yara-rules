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
        $string1 = /.{0,1000}\s\-\sRemoved\sdisabled\saccounts\sfrom\sspraying.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string2 = /.{0,1000}\s\$KerbDump.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string3 = /.{0,1000}\s\-Method\sGenRelayList.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string4 = /.{0,1000}\s\-Method\sSessionHunter.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string5 = /.{0,1000}\s\-Method\sSpray\s\-AccountAsPassword.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string6 = /.{0,1000}\s\-Method\sSpray\s\-EmptyPassword.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string7 = /.{0,1000}\s\-Method\sSpray\s\-Hash\s.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string8 = /.{0,1000}\s\-Method\sSpray\s\-Password\s.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string9 = /.{0,1000}\s\-Module\skerbdump.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string10 = /.{0,1000}\s\-Name\s\"Test\.PME\"\s.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string11 = /.{0,1000}\s\-notcontains\s.{0,1000}\s\-notlike\s\"ntuser\.dat.{0,1000}\"\s\-and\s\$_\.Extension\s\-ne\s\"\.tm.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string12 = /.{0,1000}\s\-Targets\s.{0,1000}\s\-Method\s.{0,1000}\s\-LocalAuth.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string13 = /.{0,1000}\s\-Targets\sAll\s\-Method\sWMI.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string14 = /.{0,1000}\s\-Targets\sDCs.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string15 = /.{0,1000}\swill\sbe\swritten\sto\sPME\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string16 = /.{0,1000}\"Successful\sConnection\sPME\".{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string17 = /.{0,1000}\$BaseTicket\s\|\sSelect\-String\s\-Pattern\s\'doI\..{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string18 = /.{0,1000}\$FQDNDomainPlusAccountOperators.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string19 = /.{0,1000}\$FQDNDomainPlusDomainAdmins.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string20 = /.{0,1000}\$FQDNDomainPlusEnterpriseAdmins.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string21 = /.{0,1000}\$FQDNDomainPlusServerOperators.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string22 = /.{0,1000}\$MimiTickets.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string23 = /.{0,1000}\$newClass\[\"__CLASS\"\]\s\=\s\"PMEClass\".{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string24 = /.{0,1000}\/Kirby\.ps1.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string25 = /.{0,1000}\/Kirby\.ps1.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string26 = /.{0,1000}\/PsMapExec\.git.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string27 = /.{0,1000}\/PsMapExec\/.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string28 = /.{0,1000}\[string\]\$Class\s\=\s\"PMEClass\".{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string29 = /.{0,1000}\\\.eKeys\-Parsed\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string30 = /.{0,1000}\\\\\$ComputerName\sdelete\s\$ServiceName.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string31 = /.{0,1000}\\\\.{0,1000}\screate\sService_.{0,1000}\sbinpath\=\s`\"C:\\Windows\\System32\\cmd\.exe\s\/c\spowershell\.exe\s\-enc\s.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string32 = /.{0,1000}\\Kirby\.ps1.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string33 = /.{0,1000}\\Kirby\.ps1.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string34 = /.{0,1000}\\PME\\.{0,1000}\-ConsoleHistory\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string35 = /.{0,1000}\\PME\\Console\sHistory\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string36 = /.{0,1000}\\PME\\eKeys\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string37 = /.{0,1000}\\PME\\LogonPasswords.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string38 = /.{0,1000}\\PME\\LSA\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string39 = /.{0,1000}\\PME\\MSSQL\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string40 = /.{0,1000}\\PME\\SAM\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string41 = /.{0,1000}\\PME\\Sessions\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string42 = /.{0,1000}\\PME\\SMB\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string43 = /.{0,1000}\\PME\\Spraying\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string44 = /.{0,1000}\\PME\\Tickets\\Kerbdump.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string45 = /.{0,1000}\\PME\\Tickets\\MimiTickets.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string46 = /.{0,1000}\\PME\\User\sFiles\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string47 = /.{0,1000}\\PME\\VNC\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string48 = /.{0,1000}\\SAM\\\.Sam\-Full\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string49 = /.{0,1000}\\Sessions\\SH\-MatchedGroups\-.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string50 = /.{0,1000}\\Test\.PME/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string51 = /.{0,1000}\\Tickets\\KerbDump.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string52 = /.{0,1000}\\VNC\\\.VNC\-Non\-Auth\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string53 = /.{0,1000}\|IEX}DumpSAM.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string54 = /.{0,1000}asktgt\s\/user.{0,1000}\s\/domain:.{0,1000}\s\/password:.{0,1000}\s\/opsec\s\/force\s\/ptt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string55 = /.{0,1000}Assembly\.GetType\(\"System\.Management\.Automation\.AmsiUtils\"\)\.getField\(\"amsiInitFailed\".{0,1000}\'NonPublic.{0,1000}Static\'\)\.SetValue\(\$null.{0,1000}\$true\).{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string56 = /.{0,1000}ComputerDirectory\\.{0,1000}\.FullDump\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string57 = /.{0,1000}Created\sdirectory\sfor\sPME\sat\s.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string58 = /.{0,1000}dump\s\/service:krbtgt\s.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string59 = /.{0,1000}DumpSAM\.ps1.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string60 = /.{0,1000}earching\sfor\ssystems\swhere\sprivileged\susers\'\scredentials\smight\sbe\sin\srunning\smemory.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string61 = /.{0,1000}eKeys\\.{0,1000}\-eKeys\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string62 = /.{0,1000}\-EmptyPassword\-Users\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string63 = /.{0,1000}function\sDumpSAM.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string64 = /.{0,1000}function\sGNLPH.{0,1000}Get\-ItemProperty\s\"HKLM:SAM\\SAM\\Domains\\Account\\Users\\.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string65 = /.{0,1000}Function\sPsMapExec.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string66 = /.{0,1000}Get\-GroupMembers\s\-GroupName\s\"Account\sOperators\".{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string67 = /.{0,1000}Get\-GroupMembers\s\-GroupName\s\"Domain\sAdmins\".{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string68 = /.{0,1000}Get\-GroupMembers\s\-GroupName\s\"Enterprise\sAdmins\".{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string69 = /.{0,1000}Get\-GroupMembers\s\-GroupName\s\"Server\sOperators\".{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string70 = /.{0,1000}H4sIAAAAAAAEACVQ30vDMBB.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string71 = /.{0,1000}H4sIAAAAAAAEANy9CZwcRfU43tPd093Tc.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string72 = /.{0,1000}H4sIAAAAAAAEAOx9CVhTR9fw3CQkYScgqyAILsgm.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string73 = /.{0,1000}https:\/\/github\.com\/The\-Viper\-One.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string74 = /.{0,1000}https:\/\/viperone\.gitbook\.io\/pentest\-everything.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string75 = /.{0,1000}IAS\s\-Process\s.{0,1000}aad3b435b51404eeaad3b435b51404ee.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string76 = /.{0,1000}IAS\s\-Process\s{GNLPH}.{0,1000}\$excludedUsernames\=\@\(\"Guest.{0,1000}DefaultAccount.{0,1000}WDAGUtilityAccount.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string77 = /.{0,1000}InjectTicket.{0,1000}ptt\s\/ticket:.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string78 = /.{0,1000}Invoke\-Mongoose.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string79 = /.{0,1000}Invoke\-MSSQLup.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string80 = /.{0,1000}Invoke\-NETMongoose.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string81 = /.{0,1000}Invoke\-NTDS\.ps1.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string82 = /.{0,1000}Invoke\-Pandemonium\s\-Command.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string83 = /.{0,1000}Invoke\-Pandemonium\.ps1.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string84 = /.{0,1000}Invoke\-Rubeus\s.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string85 = /.{0,1000}Invoke\-Rubeus.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string86 = /.{0,1000}Invoke\-SecretsDump\.ps1.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string87 = /.{0,1000}Invoke\-SharpRDP.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string88 = /.{0,1000}Invoke\-SharpRDPTest.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string89 = /.{0,1000}KerbDump\\.{0,1000}\-Tickets\-KerbDump\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string90 = /.{0,1000}LogonPasswords\\.{0,1000}\-LogonPasswords\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string91 = /.{0,1000}LogonPasswords\\\.AllUniqueNTLM\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string92 = /.{0,1000}MimiTickets\\.{0,1000}\-Tickets\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string93 = /.{0,1000}New\-Object\sSystem\.Management\.ManagementClass\(\"\\\\\\\$env:computername\\root\\cimv2.{0,1000}\[\"__CLASS\"\]\s\=\s\"PMEClass\".{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string94 = /.{0,1000}PME\\LSA\\.{0,1000}\-LSA\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string95 = /.{0,1000}PME\\UserFiles\\.{0,1000}\-UserFiles\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string96 = /.{0,1000}PsMapExec\s\-.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string97 = /.{0,1000}PsMapExec\swill\scontinue\sin\sthe\scurrent\susers\scontext.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string98 = /.{0,1000}PsMapExec\.ps1.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string99 = /.{0,1000}PsMapExec\-main.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string100 = /.{0,1000}SAM\\.{0,1000}\-SAMHashes\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string101 = /.{0,1000}SAM\\.{0,1000}\-SAMHashes\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string102 = /.{0,1000}SAM\\\.Sam\-Full\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string103 = /.{0,1000}SMB\\SigningNotRequired\-.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string104 = /.{0,1000}Specified\suser\sis\sa\sDomain\sAdmin\.\sUse\sthe\s\-Force\sswitch\sto\soverride.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string105 = /.{0,1000}Specified\suser\sis\sa\sEnterprise\sAdmin\.\sUse\sthe\s\-Force\sswitch\sto\soverride.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string106 = /.{0,1000}Spraying\sempty\spasswords.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string107 = /.{0,1000}Spraying\susernames\sas\spasswords.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string108 = /.{0,1000}Spraying\\.{0,1000}\-AccountAsPassword\-Users\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string109 = /.{0,1000}Spraying\\.{0,1000}\-Password\-Users\.txt.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string110 = /.{0,1000}Supply\seither\sa\s32\-character\sRC4\/NT\shash\sor\sa\s64\-character\sAES256\shash.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string111 = /.{0,1000}tgtdeleg\s\/nowrap.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string112 = /.{0,1000}The\-Viper\-One\/PME\-Scripts.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string113 = /.{0,1000}The\-Viper\-One\/PsMapExec.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string114 = /.{0,1000}to\s\$LogonPasswords.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string115 = /.{0,1000}Unhandled\sRubeus\sexception:.{0,1000}/ nocase ascii wide
        // Description: A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec.
        // Reference: https://github.com/The-Viper-One/PsMapExec
        $string116 = /.{0,1000}VNC\-NoAuth\s\-ComputerName\s.{0,1000}\s\-Port\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
