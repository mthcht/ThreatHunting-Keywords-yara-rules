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
        $string2 = /\/C2\/Http\/.{0,1000}\.cs/ nocase ascii wide
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
        $string13 = /ahsten\.run\s\\.{0,1000}powershell\.exe/ nocase ascii wide
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
        $string18 = /C2\/C2Server\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string19 = /C2Server\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string20 = /CreateC2Server/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string21 = /donut\s\-f\s.{0,1000}\.dll\s\-c\s.{0,1000}\s\-m\sRunProcess/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string22 = /donut\s\-f\sc2\.dll/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string23 = /DonutLoader\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string24 = /evilclippy\s/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string25 = /EvilClippy\.exe/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string26 = /EvilClippyManager\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string27 = /EvilClippyMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string28 = /execute\-assembly.{0,1000}Seatbelt/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string29 = /GenerateDllBase64Hta/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string30 = /GenerateExeBase64/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string31 = /GetC2Server/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string32 = /Get\-CompressedAgent/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string33 = /Get\-CompressedAgent\.ps1/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string34 = /Get\-CompressedShellcode/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string35 = /Get\-CompressedShellcode\.ps1/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string36 = /HtaPowershellGenerator\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string37 = /HtaVBSGenerator\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string38 = /HttpEvilClippyController/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string39 = /Import\spowerview/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string40 = /Keylogger\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string41 = /Mimikatz\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string42 = /MSOfficeManipulator\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string43 = /PersAutorun\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string44 = /PersCLRInstall\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string45 = /PersStartup\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string46 = /PowershellAgentGenerator\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string47 = /PowershellAmsiGenerator/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string48 = /PowershellCradleGenerator\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string49 = /PowerShellExecuter\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string50 = /PrivEscManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string51 = /PsExecMenu\(/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string52 = /RedPeanut\sSmb\sserver\sstarted/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string53 = /RedPeanut\.Models/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string54 = /redpeanut\.pfx/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string55 = /RedPeanut\.Resources\..{0,1000}\.txt/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string56 = /RedPeanut\.Utility/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string57 = /RedPeanutAgent\.C2/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string58 = /RedPeanutAgent\.Core/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string59 = /RedPeanutAgent\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string60 = /RedPeanutAgent\.Evasion/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string61 = /RedPeanutAgent\.Execution/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string62 = /RedPeanutAgent\.Program/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string63 = /RedPeanutC2/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string64 = /RedPeanutCLI/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string65 = /RedPeanutDBContext/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string66 = /RedPeanutDBInitializer/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string67 = /RedPeanutHtaPowerShellScript/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string68 = /RedPeanutHtaScript\.hta/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string69 = /RedPeanutInstallUtil\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string70 = /RedPeanutManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string71 = /RedPeanutMigrate\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string72 = /RedPeanutMSBuildScript\.xml/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string73 = /RedPeanutPowershellScriptS/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string74 = /RedPeanutRP\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string75 = /RedPeanutShooter\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string76 = /RedPeanutSpawn\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string77 = /RedPeanutSpawnTikiTorch\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string78 = /RedPeanutVBAMacro\.vba/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string79 = /rubeus\.txt/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string80 = /RubeusAskTgtMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string81 = /RubeusASREPRoastManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string82 = /RubeusChangePwManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string83 = /RubeusCreateNetOnlyManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string84 = /RubeusDescribeManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string85 = /RubeusDumpManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string86 = /RubeusDumpMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string87 = /RubeusHarvestManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string88 = /RubeusHarvestMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string89 = /RubeusHashManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string90 = /RubeusKerberoastManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string91 = /RubeusKerberoastMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string92 = /RubeusKlistManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string93 = /RubeusManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string94 = /RubeusMonitorManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string95 = /RubeusMonitorMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string96 = /RubeusPttManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string97 = /RubeusPttMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string98 = /RubeusPurgeManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string99 = /RubeusPurgeMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string100 = /RubeusRenewManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string101 = /RubeusRenewMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string102 = /RubeusS4UManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string103 = /RubeusS4UMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string104 = /RubeusTgtDelegManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string105 = /RubeusTgtDelegMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string106 = /RubeusTriageManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string107 = /SafetyKatz\.Program/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string108 = /safetykatz\.txt/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string109 = /SafetyKatzManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string110 = /sharpadidnsdump\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string111 = /SharpAdidnsdumpManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string112 = /SharpAdidnsdumpMenu/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string113 = /SharpCOMManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string114 = /SharpDPAPI/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string115 = /SharpDPAPIMachine.{0,1000}\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string116 = /SharpGPOAddComputer/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string117 = /SharpGPOAddLocalAdmin/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string118 = /SharpGPOAddUser.{0,1000}Manager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string119 = /Sharpkatz/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string120 = /SharpkatzManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string121 = /SharpMiniDump/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string122 = /SharpMiniDumpManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string123 = /sharppsexec/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string124 = /SharpPsExecManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string125 = /SharpPsExecService\./ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string126 = /SharpSpawner\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string127 = /SharpSploitDomainRecon/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string128 = /SharpSploitDomainReconImpl/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string129 = /SharpUpManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string130 = /SharpUpMenu\(/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string131 = /SharpWebManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string132 = /SharpWMI\.Program/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string133 = /SharpWmiManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string134 = /SpawnAsAgentManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string135 = /spawnasshellcode/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string136 = /SpawnAsShellcodeManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string137 = /SpawnPPIDAgentManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string138 = /SpawnShellcode\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string139 = /SpawnShellcodeManager/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string140 = /SSploitEnumeration/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string141 = /SSploitEnumerationDomain/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string142 = /SSploitExecution_DynamicInvoke/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string143 = /SSploitExecution_Injection/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string144 = /SSploitLateralMovement/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string145 = /SSploitPersistence/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string146 = /SSploitPrivilegeEscalation/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string147 = /UACTokenManipulationManager\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string148 = /using\sdonutCS/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string149 = /We\shad\sa\swoodoo/ nocase ascii wide

    condition:
        any of them
}
