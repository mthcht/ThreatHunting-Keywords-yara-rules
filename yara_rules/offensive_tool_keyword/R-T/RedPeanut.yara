rule RedPeanut
{
    meta:
        description = "Detection patterns for the tool 'RedPeanut' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedPeanut"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string1 = /\sEvilClippyManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string2 = /\/C2\/Http\/.*\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string3 = /\/C2\/SmbListener\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string4 = /\/C2Manager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string5 = /\/DonutCS\/Donut\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string6 = /\/EvilClippy/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string7 = /\/redpeanut\.cer/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string8 = /\/RedPeanut\.git/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string9 = /\/RedPeanut\.html/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string10 = /\/RedPeanutAgent\// nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string11 = /\/RedPeanutRP\// nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string12 = /\\EvilClippy/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string13 = /ahsten\.run\s\\.*powershell\.exe/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string14 = /AssmblyLoader/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string15 = /AutoCompletionHandlerC2ServerManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string16 = /b4rtik\/RedPeanut/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string17 = /b4rtik\/RedPeanut/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string18 = /C2\sServer/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string19 = /C2\/C2Server\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string20 = /C2Server\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string21 = /CreateC2Server/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string22 = /donut\s\-f\s.*\.dll\s\-c\s.*\s\-m\sRunProcess/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string23 = /donut\s\-f\sc2\.dll/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string24 = /DonutLoader\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string25 = /evilclippy\s/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string26 = /EvilClippy\.exe/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string27 = /EvilClippyManager\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string28 = /EvilClippyMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string29 = /execute\-assembly.*Seatbelt/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string30 = /GenerateDllBase64Hta/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string31 = /GenerateExeBase64/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string32 = /GetC2Server/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string33 = /Get\-CompressedAgent/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string34 = /Get\-CompressedAgent\.ps1/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string35 = /Get\-CompressedShellcode/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string36 = /Get\-CompressedShellcode\.ps1/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string37 = /HtaPowershellGenerator\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string38 = /HtaVBSGenerator\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string39 = /HttpEvilClippyController/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string40 = /ImpersonateLoggedOnUser/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string41 = /Import\spowerview/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string42 = /Keylogger\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string43 = /Mimikatz\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string44 = /MSOfficeManipulator\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string45 = /PersAutorun\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string46 = /PersCLRInstall\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string47 = /PersStartup\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string48 = /PowershellAgentGenerator\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string49 = /PowershellAmsiGenerator/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string50 = /PowershellCradleGenerator\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string51 = /PowerShellExecuter\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string52 = /PrivEscManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string53 = /PsExecMenu\(/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string54 = /RedPeanut\sSmb\sserver\sstarted/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string55 = /RedPeanut\.Models/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string56 = /redpeanut\.pfx/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string57 = /RedPeanut\.Resources\..*\.txt/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string58 = /RedPeanut\.Utility/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string59 = /RedPeanutAgent\.C2/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string60 = /RedPeanutAgent\.Core/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string61 = /RedPeanutAgent\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string62 = /RedPeanutAgent\.Evasion/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string63 = /RedPeanutAgent\.Execution/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string64 = /RedPeanutAgent\.Program/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string65 = /RedPeanutC2/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string66 = /RedPeanutCLI/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string67 = /RedPeanutDBContext/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string68 = /RedPeanutDBInitializer/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string69 = /RedPeanutHtaPowerShellScript/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string70 = /RedPeanutHtaScript\.hta/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string71 = /RedPeanutInstallUtil\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string72 = /RedPeanutManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string73 = /RedPeanutMigrate\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string74 = /RedPeanutMSBuildScript\.xml/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string75 = /RedPeanutPowershellScriptS/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string76 = /RedPeanutRP\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string77 = /RedPeanutShooter\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string78 = /RedPeanutSpawn\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string79 = /RedPeanutSpawnTikiTorch\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string80 = /RedPeanutVBAMacro\.vba/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string81 = /rubeus\.txt/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string82 = /RubeusAskTgtMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string83 = /RubeusASREPRoastManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string84 = /RubeusChangePwManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string85 = /RubeusCreateNetOnlyManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string86 = /RubeusDescribeManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string87 = /RubeusDumpManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string88 = /RubeusDumpMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string89 = /RubeusHarvestManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string90 = /RubeusHarvestMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string91 = /RubeusHashManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string92 = /RubeusKerberoastManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string93 = /RubeusKerberoastMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string94 = /RubeusKlistManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string95 = /RubeusManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string96 = /RubeusMonitorManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string97 = /RubeusMonitorMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string98 = /RubeusPttManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string99 = /RubeusPttMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string100 = /RubeusPurgeManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string101 = /RubeusPurgeMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string102 = /RubeusRenewManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string103 = /RubeusRenewMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string104 = /RubeusS4UManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string105 = /RubeusS4UMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string106 = /RubeusTgtDelegManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string107 = /RubeusTgtDelegMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string108 = /RubeusTriageManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string109 = /SafetyKatz\.Program/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string110 = /safetykatz\.txt/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string111 = /SafetyKatzManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string112 = /sharpadidnsdump\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string113 = /SharpAdidnsdumpManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string114 = /SharpAdidnsdumpMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string115 = /SharpCOMManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string116 = /SharpDPAPI/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string117 = /SharpDPAPIMachine.*\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string118 = /SharpGPOAddComputer/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string119 = /SharpGPOAddLocalAdmin/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string120 = /SharpGPOAddUser.*Manager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string121 = /Sharpkatz/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string122 = /SharpkatzManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string123 = /SharpMiniDump/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string124 = /SharpMiniDumpManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string125 = /sharppsexec/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string126 = /SharpPsExecManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string127 = /SharpPsExecService\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string128 = /SharpSpawner\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string129 = /SharpSploitDomainRecon/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string130 = /SharpSploitDomainReconImpl/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string131 = /SharpUpManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string132 = /SharpUpMenu\(/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string133 = /SharpWebManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string134 = /SharpWMI\.Program/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string135 = /SharpWmiManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string136 = /SpawnAsAgentManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string137 = /spawnasshellcode/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string138 = /SpawnAsShellcodeManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string139 = /SpawnPPIDAgentManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string140 = /SpawnShellcode\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string141 = /SpawnShellcodeManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string142 = /SSploitEnumeration/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string143 = /SSploitEnumerationDomain/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string144 = /SSploitExecution_DynamicInvoke/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string145 = /SSploitExecution_Injection/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string146 = /SSploitLateralMovement/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string147 = /SSploitPersistence/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string148 = /SSploitPrivilegeEscalation/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string149 = /UACTokenManipulationManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string150 = /using\sdonutCS/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string151 = /We\shad\sa\swoodoo/ nocase ascii wide

    condition:
        any of them
}