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
        $string1 = /.{0,1000}\sEvilClippyManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string2 = /.{0,1000}\/C2\/Http\/.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string3 = /.{0,1000}\/C2\/SmbListener\..{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string4 = /.{0,1000}\/C2Manager\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string5 = /.{0,1000}\/DonutCS\/Donut\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string6 = /.{0,1000}\/EvilClippy.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string7 = /.{0,1000}\/redpeanut\.cer.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string8 = /.{0,1000}\/RedPeanut\.git.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string9 = /.{0,1000}\/RedPeanut\.html.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string10 = /.{0,1000}\/RedPeanutAgent\/.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string11 = /.{0,1000}\/RedPeanutRP\/.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string12 = /.{0,1000}\\EvilClippy.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string13 = /.{0,1000}ahsten\.run\s\\.{0,1000}powershell\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string14 = /.{0,1000}AssmblyLoader.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string15 = /.{0,1000}AutoCompletionHandlerC2ServerManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string16 = /.{0,1000}b4rtik\/RedPeanut.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string17 = /.{0,1000}b4rtik\/RedPeanut.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string18 = /.{0,1000}C2\sServer.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string19 = /.{0,1000}C2\/C2Server\..{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string20 = /.{0,1000}C2Server\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string21 = /.{0,1000}CreateC2Server.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string22 = /.{0,1000}donut\s\-f\s.{0,1000}\.dll\s\-c\s.{0,1000}\s\-m\sRunProcess.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string23 = /.{0,1000}donut\s\-f\sc2\.dll.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string24 = /.{0,1000}DonutLoader\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string25 = /.{0,1000}evilclippy\s.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string26 = /.{0,1000}EvilClippy\.exe.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string27 = /.{0,1000}EvilClippyManager\..{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string28 = /.{0,1000}EvilClippyMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string29 = /.{0,1000}execute\-assembly.{0,1000}Seatbelt.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string30 = /.{0,1000}GenerateDllBase64Hta.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string31 = /.{0,1000}GenerateExeBase64.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string32 = /.{0,1000}GetC2Server.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string33 = /.{0,1000}Get\-CompressedAgent.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string34 = /.{0,1000}Get\-CompressedAgent\.ps1.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string35 = /.{0,1000}Get\-CompressedShellcode.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string36 = /.{0,1000}Get\-CompressedShellcode\.ps1.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string37 = /.{0,1000}HtaPowershellGenerator\..{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string38 = /.{0,1000}HtaVBSGenerator\..{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string39 = /.{0,1000}HttpEvilClippyController.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string40 = /.{0,1000}ImpersonateLoggedOnUser.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string41 = /.{0,1000}Import\spowerview.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string42 = /.{0,1000}Keylogger\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string43 = /.{0,1000}Mimikatz\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string44 = /.{0,1000}MSOfficeManipulator\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string45 = /.{0,1000}PersAutorun\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string46 = /.{0,1000}PersCLRInstall\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string47 = /.{0,1000}PersStartup\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string48 = /.{0,1000}PowershellAgentGenerator\..{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string49 = /.{0,1000}PowershellAmsiGenerator.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string50 = /.{0,1000}PowershellCradleGenerator\..{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string51 = /.{0,1000}PowerShellExecuter\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string52 = /.{0,1000}PrivEscManager\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string53 = /.{0,1000}PsExecMenu\(.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string54 = /.{0,1000}RedPeanut\sSmb\sserver\sstarted.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string55 = /.{0,1000}RedPeanut\.Models.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string56 = /.{0,1000}redpeanut\.pfx.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string57 = /.{0,1000}RedPeanut\.Resources\..{0,1000}\.txt/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string58 = /.{0,1000}RedPeanut\.Utility.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string59 = /.{0,1000}RedPeanutAgent\.C2.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string60 = /.{0,1000}RedPeanutAgent\.Core.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string61 = /.{0,1000}RedPeanutAgent\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string62 = /.{0,1000}RedPeanutAgent\.Evasion.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string63 = /.{0,1000}RedPeanutAgent\.Execution.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string64 = /.{0,1000}RedPeanutAgent\.Program.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string65 = /.{0,1000}RedPeanutC2.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string66 = /.{0,1000}RedPeanutCLI.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string67 = /.{0,1000}RedPeanutDBContext.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string68 = /.{0,1000}RedPeanutDBInitializer.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string69 = /.{0,1000}RedPeanutHtaPowerShellScript.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string70 = /.{0,1000}RedPeanutHtaScript\.hta.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string71 = /.{0,1000}RedPeanutInstallUtil\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string72 = /.{0,1000}RedPeanutManager\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string73 = /.{0,1000}RedPeanutMigrate\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string74 = /.{0,1000}RedPeanutMSBuildScript\.xml.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string75 = /.{0,1000}RedPeanutPowershellScriptS.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string76 = /.{0,1000}RedPeanutRP\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string77 = /.{0,1000}RedPeanutShooter\..{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string78 = /.{0,1000}RedPeanutSpawn\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string79 = /.{0,1000}RedPeanutSpawnTikiTorch\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string80 = /.{0,1000}RedPeanutVBAMacro\.vba.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string81 = /.{0,1000}rubeus\.txt.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string82 = /.{0,1000}RubeusAskTgtMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string83 = /.{0,1000}RubeusASREPRoastManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string84 = /.{0,1000}RubeusChangePwManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string85 = /.{0,1000}RubeusCreateNetOnlyManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string86 = /.{0,1000}RubeusDescribeManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string87 = /.{0,1000}RubeusDumpManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string88 = /.{0,1000}RubeusDumpMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string89 = /.{0,1000}RubeusHarvestManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string90 = /.{0,1000}RubeusHarvestMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string91 = /.{0,1000}RubeusHashManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string92 = /.{0,1000}RubeusKerberoastManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string93 = /.{0,1000}RubeusKerberoastMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string94 = /.{0,1000}RubeusKlistManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string95 = /.{0,1000}RubeusManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string96 = /.{0,1000}RubeusMonitorManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string97 = /.{0,1000}RubeusMonitorMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string98 = /.{0,1000}RubeusPttManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string99 = /.{0,1000}RubeusPttMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string100 = /.{0,1000}RubeusPurgeManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string101 = /.{0,1000}RubeusPurgeMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string102 = /.{0,1000}RubeusRenewManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string103 = /.{0,1000}RubeusRenewMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string104 = /.{0,1000}RubeusS4UManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string105 = /.{0,1000}RubeusS4UMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string106 = /.{0,1000}RubeusTgtDelegManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string107 = /.{0,1000}RubeusTgtDelegMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string108 = /.{0,1000}RubeusTriageManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string109 = /.{0,1000}SafetyKatz\.Program.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string110 = /.{0,1000}safetykatz\.txt.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string111 = /.{0,1000}SafetyKatzManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string112 = /.{0,1000}sharpadidnsdump\..{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string113 = /.{0,1000}SharpAdidnsdumpManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string114 = /.{0,1000}SharpAdidnsdumpMenu.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string115 = /.{0,1000}SharpCOMManager\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string116 = /.{0,1000}SharpDPAPI.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string117 = /.{0,1000}SharpDPAPIMachine.{0,1000}\.cs/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string118 = /.{0,1000}SharpGPOAddComputer.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string119 = /.{0,1000}SharpGPOAddLocalAdmin.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string120 = /.{0,1000}SharpGPOAddUser.{0,1000}Manager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string121 = /.{0,1000}Sharpkatz.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string122 = /.{0,1000}SharpkatzManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string123 = /.{0,1000}SharpMiniDump.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string124 = /.{0,1000}SharpMiniDumpManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string125 = /.{0,1000}sharppsexec.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string126 = /.{0,1000}SharpPsExecManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string127 = /.{0,1000}SharpPsExecService\..{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string128 = /.{0,1000}SharpSpawner\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string129 = /.{0,1000}SharpSploitDomainRecon.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string130 = /.{0,1000}SharpSploitDomainReconImpl.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string131 = /.{0,1000}SharpUpManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string132 = /.{0,1000}SharpUpMenu\(.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string133 = /.{0,1000}SharpWebManager\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string134 = /.{0,1000}SharpWMI\.Program.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string135 = /.{0,1000}SharpWmiManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string136 = /.{0,1000}SpawnAsAgentManager\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string137 = /.{0,1000}spawnasshellcode.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string138 = /.{0,1000}SpawnAsShellcodeManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string139 = /.{0,1000}SpawnPPIDAgentManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string140 = /.{0,1000}SpawnShellcode\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string141 = /.{0,1000}SpawnShellcodeManager.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string142 = /.{0,1000}SSploitEnumeration.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string143 = /.{0,1000}SSploitEnumerationDomain.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string144 = /.{0,1000}SSploitExecution_DynamicInvoke.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string145 = /.{0,1000}SSploitExecution_Injection.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string146 = /.{0,1000}SSploitLateralMovement.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string147 = /.{0,1000}SSploitPersistence.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string148 = /.{0,1000}SSploitPrivilegeEscalation.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string149 = /.{0,1000}UACTokenManipulationManager\.cs.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string150 = /.{0,1000}using\sdonutCS.{0,1000}/ nocase ascii wide
        // Description: RedPeanut is a small RAT developed in .Net Core 2 and its agent in .Net 3.5 / 4.0.
        // Reference: https://github.com/b4rtik/RedPeanut
        $string151 = /.{0,1000}We\shad\sa\swoodoo.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
