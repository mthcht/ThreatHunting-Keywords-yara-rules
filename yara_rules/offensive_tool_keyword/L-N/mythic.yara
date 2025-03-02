rule mythic
{
    meta:
        description = "Detection patterns for the tool 'mythic' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mythic"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string1 = /\sAthena\.Commands/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string2 = /\sAthena\.Models\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string3 = /\sathena\.mythic/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string4 = " c2 add " nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string5 = " c2 start http " nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string6 = /\sDInvokeResolver\./ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string7 = /\sinstall\sgithub\s.{0,1000}merlin/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string8 = /\smerlin\.py\s/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string9 = " mythic start" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string10 = /\smythic_container\.Mythic/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string11 = " mythic_payloadtype_container" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string12 = " mythic-cli" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string13 = " payload add " nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string14 = " tdotnet publish Athena " nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string15 = /\.athena_utils\s/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string16 = /\.get_c2profile/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string17 = /\/adcs\-enum\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string18 = "/agent_code/Apollo/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string19 = "/agent_code/Athena" nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string20 = "/agent_code/cmd_executor" nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string21 = /\/agent_code\/dll\.go/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string22 = /\/agent_code\/merlin\./ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string23 = "/agent_code/powershell_executor" nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string24 = "/agent_code/sh_executor" nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string25 = "/agent_code/zsh_executor" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string26 = /\/agent_functions\/.{0,1000}\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string27 = /\/agent_icons\/athena\.svg/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string28 = "/agents/thanatos/commands/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string29 = /\/amsi\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string30 = /\/Apollo\.exe/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string31 = /\/Apollo\.git/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string32 = "/Apollo/Agent/" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string33 = /\/ApolloInterop\./ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string34 = "/ApolloInterop/" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string35 = /\/ApolloTest\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string36 = /\/Athena\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string37 = /\/Athena\.csproj/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string38 = /\/Athena\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string39 = /\/Athena\.Profiles\..{0,1000}\.cs/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string40 = /\/Athena\.Profiles\..{0,1000}\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string41 = /\/Athena\.Profiles\..{0,1000}\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string42 = /\/Athena\.sln/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string43 = /\/Athena\/Assembly\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string44 = /\/Athena\/Commands\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string45 = "/athena/mythic" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string46 = /\/athena_utils\/.{0,1000}\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string47 = "/AthenaPlugins/bin/"
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string48 = "/AthenaSMB/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string49 = /\/AthenaTests\/.{0,1000}\./ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string50 = /\/bash_executor\/.{0,1000}\.go/
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string51 = /\/c2_code\/.{0,1000}\.html/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string52 = "/c2_code/server" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string53 = "/C2_Profiles/" nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string54 = /\/cmd_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string55 = "/DInvoke/" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string56 = "/DInvokeResolver/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string57 = "/documentation-c2/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string58 = "/documentation-payload/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string59 = /\/enable\-user\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string60 = "/Example_C2_Profile" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string61 = "/Example_Payload_Type/" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string62 = /\/fake\.html/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string63 = /\/freyja\.go/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string64 = "/freyja_tcp/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string65 = /\/get\-clipboard\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string66 = /\/inline\-exec\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string67 = /\/kerberoast\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string68 = /\/kerberoast\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string69 = /\/kerberoast\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string70 = /\/keylogger\/.{0,1000}\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string71 = /\/load\-assembly\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string72 = "/Management/C2/" nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string73 = /\/merlin\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string74 = "/merlin/agent_code/" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string75 = "/Mythic/mythic" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string76 = "/Mythic_CLI" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string77 = "/MythicAgents/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string78 = "/MythicAgents/" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string79 = "/MythicC2Profiles/" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string80 = "/mythic-cli" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string81 = /\/MythicConfig\.cs/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string82 = "/mythic-react-docker" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string83 = "/nanorubeus/" nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string84 = "/opt/merlin/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string85 = "/outflank_bofs/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string86 = /\/payload_service\.sh/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string87 = "/Payload_Type/athena" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string88 = "/Payload_Types/" nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string89 = /\/powershell_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string90 = /\/schtasksenum\/.{0,1000}\./ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string91 = "/ScreenshotInject" nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string92 = /\/sh_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string93 = /\/SMBForwarder\.txt/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string94 = /\/thanatos\.dll/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string95 = /\/thanatos\.exe/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string96 = /\/thanatos\.git/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string97 = "/thanatos/releases/" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string98 = "/thanatos/releases/latest" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string99 = "/thanatos/thanatos/agent_code/"
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string100 = /\/timestomp\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string101 = "/trusted_sec_bofs/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string102 = "/trusted_sec_remote_bofs/" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string103 = "/UACBypasses/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string104 = /\/vss\-enum\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string105 = "/win-enum-resources" nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string106 = /\/zsh_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string107 = /\\Apollo\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string108 = /\\Athena\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string109 = /\\thanatos\.dll/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string110 = /\\thanatos\.exe/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string111 = "04211dce315cd4a178578452d67ed6cb281073f05d70ad51b758131171b1a072" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string112 = "062c58fd40ba2db0ca413999598afee2beabf79f16ca0308c0565e19614d8487" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string113 = "10d06380c1904999c36072f962cfe380fe36488c3bcf1a2f485532de4d5bae5f" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string114 = "12aa6879942823c8807fa8fb30e248e1c0504c2588995ff6930c446eb2b999d5" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string115 = "16d582a5722d39a87d530e62c732864b8eeb9b039ca9b769888e53539b21371e" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string116 = "1eca6224c1b88fb220bbfa728cf27f260fb1ea27d5520167fd98ca25b0e5c1c8" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string117 = "20749471886fbeb543555c1060694f64891eb0a41adae19f747b2c635b2a3a94" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string118 = "27f443acc6d3ba9588017121dc2e70f8aed6224a69d8f41b0a51afb21b8fd259" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string119 = "331494b772e936769247a43746a6ac828257c145cb3e514e8682ceb5d58af06f" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string120 = "3c625eb5dbccce53faab97b9bfd0ef14f6c08730eae0d6442d201a64597c96ea" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string121 = "5059f0c09b5561445b48a8566a3754caf1472f8539194b35428bb3ff7690f06e" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string122 = "590cdf2dfb21bf5ee5fcdfe1f37bd530cbd946cfcc43f8e644638486b06cdc18" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string123 = "7443/new/payloads" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string124 = "7d621fe424daf7ca2a90cc1167ae8a9fc8eca96c82821acf6a2fa3fe7683603c" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string125 = "894399f27a67fa61608ef9a098bf9dc3ec009582d98193616cde9ab3b59f7a51" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string126 = "ab945e611084c9deccab6780df91caadf44977d54e61f621d2a5686a217a0a73" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string127 = "ae136c5aa1e9a4524f30350fc8fc45993e2a81d0ffab2d7c4bd0f9ae7cea2060" nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string128 = "agent_code/bash_executor"
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string129 = /Athena\.Forwarders\.SMB/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string130 = "athena/agent_code/" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string131 = /AthenaPlugins\.csproj/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string132 = "bash_executor "
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string133 = "bdf481e2b241169231c72a3f811c69f97526db060e11c2e7e7c1e39dadf4ac89" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string134 = "blockdlls -" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string135 = /build\.ps1\s\-commands\s.{0,1000}\s\-profile\s.{0,1000}selfcontained\s\-singlefile/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string136 = /build\.ps1\s\-profiles\s.{0,1000}\s\-commands\s.{0,1000}\s\-compressed/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string137 = /C2_RPC_functions\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string138 = /c2_service\.sh/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string139 = /C2ProfileManager\./ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string140 = "cdd738401073d7c2c6b919b1a97e136c12467c6ccfbdc1f8b55baa67e4f9afe7" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string141 = "-cli install github " nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string142 = /\-cli\sinstall\sgithub\s.{0,1000}Apollo\./ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string143 = "-cli payload start " nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string144 = "cmd_executor " nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string145 = "d65a63d32b46e3b20f42174834f5a367ab0ffbfc1b0bd4b368613c86d01a71e2" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string146 = "dcsync -Domain" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string147 = /docs\.mythic\-c2\.net/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string148 = "e542e94c43340357ded227e309c20e1e03505295a8dba216781f2976ff29c449" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string149 = "execute_pe -PE" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string150 = /execute\-assembly\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string151 = /execute\-pe\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string152 = /execute\-shellcode\.py/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string153 = "f9c1f7d62460e7ab424bacb00361ec645816cf478c9308ede41ac926c5012db3" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string154 = "fb8b5d212f449a8ba61ab9ed9b44853315c33d12a07f8ce4642892750e251530" nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string155 = "from merlin import " nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string156 = /from\smythic_container\.MythicCommandBase/ nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string157 = /from\smythic_container\.MythicGoRPC/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string158 = "get_injection_techniques" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string159 = /GETCLIPBOARD.{0,1000}GETLOCALGROUP/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string160 = /get\-password\-policy\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string161 = /github\.com\/MythicAgents\// nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string162 = /golden_ticket\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string163 = /http\:\/\/127\.0\.0\.1\:7444/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string164 = /https\:\/\/127\.0\.0\.1\:7443/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string165 = "import mythic" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string166 = "inline_assembly -Assembly " nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string167 = /inline\-exec\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string168 = "issue_shell_whoami" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string169 = "its-a-feature/Apfell" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string170 = "its-a-feature/Mythic" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string171 = "its-a-feature/Mythic" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string172 = "keylog_inject " nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string173 = /keylog_inject\.py/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string174 = /killprocess\.py/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string175 = /link_tcp\s127\.0\.0\.1\s/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string176 = /merlin\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string177 = "mimikatz -Command " nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string178 = "MockDirUACBypassDll" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string179 = "mythic_c2_container" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string180 = "mythic_nginx" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string181 = "mythic_payloadtype" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string182 = "mythic_payloadtype" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string183 = "mythic_payloadtype_container" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string184 = /mythic_rest\.Payload/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string185 = /mythic_service\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string186 = "mythic_translator_containter" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string187 = "MythicAgents/Apollo" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string188 = "MythicAgents/Athena" nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string189 = "MythicAgents/merlin" nocase ascii wide
        // Description: Thanatos is a Windows and Linux C2 agent written in rust.
        // Reference: https://github.com/MythicAgents/thanatos
        $string190 = "MythicAgents/thanatos" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string191 = "mythic-cli " nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string192 = /mythic\-cli.{0,1000}athena/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string193 = /MythicClient\.cs/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string194 = "mythic-docker" nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string195 = /nanorobeus\.x64\./ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string196 = /nanorubeus\./ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string197 = "net_dclist " nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string198 = "net_localgroup_member -Group" nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string199 = "Payload_Type/freyja/" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string200 = /\-PID\s.{0,1000}\s\-Assembly\s.{0,1000}\s\-Arguments\s/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string201 = "powerpick -Command " nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string202 = "printspoofer -Command" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string203 = /printspoofer\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string204 = /PrintSpoofer_x64\.exe/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string205 = "psinject -PID" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string206 = /run\s\-Executable\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string207 = "screenshot_inject " nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string208 = "set_injection_technique" nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string209 = /setup_apfell\.sh/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string210 = "spawnto_x64 -Application " nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string211 = /spawnto_x64\.py/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string212 = "spawnto_x86 -Application" nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string213 = /spawnto_x86\.py/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string214 = /start_mythic_server\.sh/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string215 = "steal_token " nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string216 = /steal_token\.py/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string217 = /TicketToHashcat\.py/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string218 = "zsh_executor " nocase ascii wide

    condition:
        any of them
}
