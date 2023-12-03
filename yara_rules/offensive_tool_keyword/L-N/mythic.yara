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
        $string1 = /.{0,1000}\sAthena\.Commands.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string2 = /.{0,1000}\sAthena\.Models\..{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string3 = /.{0,1000}\sathena\.mythic.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string4 = /.{0,1000}\sc2\sadd\s.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string5 = /.{0,1000}\sc2\sstart\shttp\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string6 = /.{0,1000}\sDInvokeResolver\..{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string7 = /.{0,1000}\sinstall\sgithub\s.{0,1000}merlin.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string8 = /.{0,1000}\smerlin\.py\s.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string9 = /.{0,1000}\smythic\sstart.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string10 = /.{0,1000}\smythic_container\.Mythic.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string11 = /.{0,1000}\smythic_payloadtype_container.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string12 = /.{0,1000}\smythic\-cli.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string13 = /.{0,1000}\spayload\sadd\s.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string14 = /.{0,1000}\spayload\sstart\s.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string15 = /.{0,1000}\stdotnet\spublish\sAthena\s.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string16 = /.{0,1000}\.athena_utils\s.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string17 = /.{0,1000}\.get_c2profile.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string18 = /.{0,1000}\/adcs\-enum\.py.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string19 = /.{0,1000}\/agent_code\/Apollo\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string20 = /.{0,1000}\/agent_code\/Athena.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string21 = /.{0,1000}\/agent_code\/cmd_executor.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string22 = /.{0,1000}\/agent_code\/dll\.go.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string23 = /.{0,1000}\/agent_code\/merlin\..{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string24 = /.{0,1000}\/agent_code\/powershell_executor.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string25 = /.{0,1000}\/agent_code\/sh_executor.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string26 = /.{0,1000}\/agent_code\/zsh_executor.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string27 = /.{0,1000}\/agent_functions\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string28 = /.{0,1000}\/agent_icons\/athena\.svg.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string29 = /.{0,1000}\/amsi\.py.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string30 = /.{0,1000}\/Apollo\.exe.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string31 = /.{0,1000}\/Apollo\.git.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string32 = /.{0,1000}\/Apollo\/Agent\/.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string33 = /.{0,1000}\/ApolloInterop\..{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string34 = /.{0,1000}\/ApolloInterop\/.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string35 = /.{0,1000}\/ApolloTest\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string36 = /.{0,1000}\/Athena\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string37 = /.{0,1000}\/Athena\.csproj.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string38 = /.{0,1000}\/Athena\.exe.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string39 = /.{0,1000}\/Athena\.Profiles\..{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string40 = /.{0,1000}\/Athena\.Profiles\..{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string41 = /.{0,1000}\/Athena\.Profiles\..{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string42 = /.{0,1000}\/Athena\.sln.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string43 = /.{0,1000}\/Athena\/Assembly\/.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string44 = /.{0,1000}\/Athena\/Commands\/.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string45 = /.{0,1000}\/athena\/mythic.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string46 = /.{0,1000}\/athena_utils\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string47 = /.{0,1000}\/AthenaPlugins\/bin\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string48 = /.{0,1000}\/AthenaSMB\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string49 = /.{0,1000}\/AthenaTests\/.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string50 = /.{0,1000}\/bash_executor\/.{0,1000}\.go/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string51 = /.{0,1000}\/c2_code\/.{0,1000}\.html/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string52 = /.{0,1000}\/c2_code\/server.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string53 = /.{0,1000}\/C2_Profiles\/.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string54 = /.{0,1000}\/cmd_executor\/.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string55 = /.{0,1000}\/DInvoke\/.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string56 = /.{0,1000}\/DInvokeResolver\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string57 = /.{0,1000}\/documentation\-c2\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string58 = /.{0,1000}\/documentation\-payload\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string59 = /.{0,1000}\/enable\-user\.py.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string60 = /.{0,1000}\/Example_C2_Profile.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string61 = /.{0,1000}\/Example_Payload_Type\/.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string62 = /.{0,1000}\/fake\.html/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string63 = /.{0,1000}\/freyja\.go.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string64 = /.{0,1000}\/freyja_tcp\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string65 = /.{0,1000}\/get\-clipboard\.py.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string66 = /.{0,1000}\/inline\-exec\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string67 = /.{0,1000}\/kerberoast\..{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string68 = /.{0,1000}\/kerberoast\.py.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string69 = /.{0,1000}\/kerberoast\/.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string70 = /.{0,1000}\/keylogger\/.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string71 = /.{0,1000}\/load\-assembly\.py.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string72 = /.{0,1000}\/Management\/C2\/.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string73 = /.{0,1000}\/merlin\.py.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string74 = /.{0,1000}\/merlin\/agent_code\/.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string75 = /.{0,1000}\/Mythic\/mythic.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string76 = /.{0,1000}\/Mythic_CLI.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string77 = /.{0,1000}\/MythicAgents\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string78 = /.{0,1000}\/MythicAgents\/.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string79 = /.{0,1000}\/MythicC2Profiles\/.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string80 = /.{0,1000}\/mythic\-cli.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string81 = /.{0,1000}\/MythicConfig\.cs.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string82 = /.{0,1000}\/mythic\-react\-docker.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string83 = /.{0,1000}\/nanorubeus\/.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string84 = /.{0,1000}\/opt\/merlin\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string85 = /.{0,1000}\/outflank_bofs\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string86 = /.{0,1000}\/payload_service\.sh.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string87 = /.{0,1000}\/Payload_Type\/athena.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string88 = /.{0,1000}\/Payload_Types\/.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string89 = /.{0,1000}\/powershell_executor\/.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string90 = /.{0,1000}\/schtasksenum\/.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string91 = /.{0,1000}\/ScreenshotInject.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string92 = /.{0,1000}\/sh_executor\/.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string93 = /.{0,1000}\/SMBForwarder\.txt.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string94 = /.{0,1000}\/timestomp\.py.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string95 = /.{0,1000}\/trusted_sec_bofs\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string96 = /.{0,1000}\/trusted_sec_remote_bofs\/.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string97 = /.{0,1000}\/UACBypasses\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string98 = /.{0,1000}\/vss\-enum\.py.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string99 = /.{0,1000}\/win\-enum\-resources.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string100 = /.{0,1000}\/zsh_executor\/.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string101 = /.{0,1000}\\Apollo\.exe.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string102 = /.{0,1000}\\Athena\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string103 = /.{0,1000}7443\/new\/payloads.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string104 = /.{0,1000}agent_code\/bash_executor.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string105 = /.{0,1000}assembly_inject\s\-.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string106 = /.{0,1000}Athena\.Forwarders\.SMB.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string107 = /.{0,1000}athena\/agent_code\/.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string108 = /.{0,1000}AthenaPlugins\.csproj.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string109 = /.{0,1000}bash_executor\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string110 = /.{0,1000}blockdlls\s\-.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string111 = /.{0,1000}build\.ps1\s\-commands\s.{0,1000}\s\-profile\s.{0,1000}selfcontained\s\-singlefile.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string112 = /.{0,1000}build\.ps1\s\-profiles\s.{0,1000}\s\-commands\s.{0,1000}\s\-compressed.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string113 = /.{0,1000}C2_RPC_functions\.py.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string114 = /.{0,1000}c2_service\.sh.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string115 = /.{0,1000}C2ProfileManager\..{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string116 = /.{0,1000}\-cli\sinstall\sgithub\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string117 = /.{0,1000}\-cli\sinstall\sgithub\s.{0,1000}Apollo\..{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string118 = /.{0,1000}\-cli\spayload\sstart\s.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string119 = /.{0,1000}cmd_executor\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string120 = /.{0,1000}dcsync\s\-Domain.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string121 = /.{0,1000}execute_assembly\s\-Assembly\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string122 = /.{0,1000}execute_pe\s\-PE.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string123 = /.{0,1000}ExecuteAssembly\..{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string124 = /.{0,1000}execute\-assembly\.py.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string125 = /.{0,1000}execute\-pe\.py.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string126 = /.{0,1000}execute\-shellcode\.py.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string127 = /.{0,1000}fb8b5d212f449a8ba61ab9ed9b44853315c33d12a07f8ce4642892750e251530.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string128 = /.{0,1000}from\smerlin\simport\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string129 = /.{0,1000}get_injection_techniques.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string130 = /.{0,1000}GETCLIPBOARD.{0,1000}GETLOCALGROUP.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string131 = /.{0,1000}get\-password\-policy\.py.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string132 = /.{0,1000}github\.com\/MythicAgents\/.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string133 = /.{0,1000}golden_ticket\.py.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string134 = /.{0,1000}http:\/\/127\.0\.0\.1:7444.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string135 = /.{0,1000}https:\/\/127\.0\.0\.1:7443.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string136 = /.{0,1000}import\smythic.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string137 = /.{0,1000}inline_assembly\s\-Assembly\s.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string138 = /.{0,1000}inline\-exec\.py.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string139 = /.{0,1000}issue_shell_whoami.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string140 = /.{0,1000}its\-a\-feature\/Apfell.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string141 = /.{0,1000}its\-a\-feature\/Mythic.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string142 = /.{0,1000}its\-a\-feature\/Mythic.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string143 = /.{0,1000}keylog_inject\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string144 = /.{0,1000}keylog_inject\.py.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string145 = /.{0,1000}killprocess\.py.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string146 = /.{0,1000}link_tcp\s127\.0\.0\.1\s.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string147 = /.{0,1000}merlin\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string148 = /.{0,1000}mimikatz\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string149 = /.{0,1000}MockDirUACBypassDll.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string150 = /.{0,1000}mythic_c2_container.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string151 = /.{0,1000}mythic_nginx.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string152 = /.{0,1000}mythic_payloadtype.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string153 = /.{0,1000}mythic_payloadtype.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string154 = /.{0,1000}mythic_payloadtype_container.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string155 = /.{0,1000}mythic_rest\.Payload.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string156 = /.{0,1000}mythic_service\.py.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string157 = /.{0,1000}mythic_translator_containter.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string158 = /.{0,1000}MythicAgents\/Apollo.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string159 = /.{0,1000}MythicAgents\/Athena.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string160 = /.{0,1000}MythicAgents\/merlin.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string161 = /.{0,1000}mythic\-cli\s.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string162 = /.{0,1000}mythic\-cli.{0,1000}athena.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string163 = /.{0,1000}MythicClient\.cs.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string164 = /.{0,1000}mythic\-docker.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string165 = /.{0,1000}nanorobeus\.x64\..{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string166 = /.{0,1000}nanorubeus\..{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string167 = /.{0,1000}net_dclist\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string168 = /.{0,1000}net_localgroup_member\s\-Group.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string169 = /.{0,1000}Payload_Type\/freyja\/.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string170 = /.{0,1000}\-PID\s.{0,1000}\s\-Assembly\s.{0,1000}\s\-Arguments\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string171 = /.{0,1000}powerpick\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string172 = /.{0,1000}printspoofer\s\-Command.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string173 = /.{0,1000}printspoofer\.py.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string174 = /.{0,1000}PrintSpoofer_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string175 = /.{0,1000}psinject\s\-PID.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string176 = /.{0,1000}run\s\-Executable\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string177 = /.{0,1000}screenshot_inject\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string178 = /.{0,1000}set_injection_technique.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string179 = /.{0,1000}setup_apfell\.sh.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string180 = /.{0,1000}spawnto_x64\s\-Application\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string181 = /.{0,1000}spawnto_x64\.py.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string182 = /.{0,1000}spawnto_x86\s\-Application.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string183 = /.{0,1000}spawnto_x86\.py.{0,1000}/ nocase ascii wide
        // Description: A collaborative multi-platform red teaming framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string184 = /.{0,1000}start_mythic_server\.sh.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string185 = /.{0,1000}steal_token\s.{0,1000}/ nocase ascii wide
        // Description: Cross-platform post-exploitation HTTP Command & Control agent written in golang
        // Reference: https://github.com/MythicAgents/merlin
        $string186 = /.{0,1000}steal_token\.py.{0,1000}/ nocase ascii wide
        // Description: Athena is a fully-featured cross-platform agent designed using the .NET 6. Athena is designed for Mythic 2.2 and newer
        // Reference: https://github.com/MythicAgents/Athena
        $string187 = /.{0,1000}TicketToHashcat\.py.{0,1000}/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string188 = /.{0,1000}zsh_executor\s.{0,1000}/ nocase ascii wide
        // Description: A .NET Framework 4.0 Windows Agent
        // Reference: https://github.com/MythicAgents/Apollo/
        $string189 = /getprivs/ nocase ascii wide
        // Description: mythic C2 agent
        // Reference: https://github.com/MythicAgents/freyja/
        $string190 = /sh_executor\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
