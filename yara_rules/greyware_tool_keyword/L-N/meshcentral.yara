rule meshcentral
{
    meta:
        description = "Detection patterns for the tool 'meshcentral' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "meshcentral"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string1 = /\sinstall\smeshcentral/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string2 = /\smeshcentral\.service/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string3 = /\s\-omeshcmd\.exe\s\-imodule1\.js/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string4 = /\.meshagent\.pid/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string5 = /\/bin\/meshagent/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string6 = /\/bin\/MeshCommander/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string7 = /\/MeshAgent\s\-\-/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string8 = /\/MeshAgent\.git/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string9 = /\/MeshCentral\.git/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string10 = /\/meshcentral\.service/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string11 = /\/meshinstall\.sh/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string12 = /\/meshinstall\-bsd\-rcd\.sh/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string13 = /\/system\/meshagent/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string14 = /\/system\/MeshCommander/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string15 = /\\\\MeshAgent/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string16 = /\\CurrentControlSet\\Services\\Mesh/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string17 = /\\meshagent\.db/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string18 = /\\MeshAgent\.sln/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string19 = /\\MeshAgentKvm\.log/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string20 = /\\MeshAgent\-master/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string21 = /\\meshcentral\.db/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string22 = /\\meshcentral\.js/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string23 = /\\MeshCentral\.sln/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string24 = /\\MeshCentral\\/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string25 = /\\MeshCmd\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string26 = /\\meshcmd\.js/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string27 = /\\meshcommander\.dmp/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string28 = /\\MeshMessenger\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string29 = /\\MeshService\.rc/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string30 = /\\node_modules\\meshcentral/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string31 = /\\Open\sSource\\MeshCentral\\/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string32 = /\\Safeboot\\Network\\AltMeshAgent/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string33 = /\\Uninstall\\MeshCentralAgent/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string34 = /\>Mesh\sAgent\sbackground\sservice\</ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string35 = /\>Mesh\sAgent\sCompany\</ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string36 = /\>meshagentRepair\</ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string37 = /\>MeshCentral\sAgent\</ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string38 = /\>MeshCentral\</ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string39 = /035cf1744ffefef60ff711aeae4bcf39cd902e0a581b443553545f6b934f2a71/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string40 = /03A09084\-0576\-45C5\-97CA\-B83B1A8688B8/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string41 = /127ec181a70d665e539d93b8e4a014ce099faf64f0eb790a85158cd5a1349bfd/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string42 = /128C450F\-C8B3\-403A\-9D0C\-E5AD6B7F566F/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string43 = /169fa5bf73c73e2785691de174d40209dfa479430539acbce08eaf24a4cbb0c0/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string44 = /196d1f2b496f00ed154b1ea8884ee7e5938504750c79d9d3e345d47db5499980/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string45 = /1e5aad914ec6f6fdbb0c0c340ab0e2c336922fba3e556b007d8d5002a6c478ca/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string46 = /1f2cf255b1a6d9fafad11a2d27bc9471f1e883c59a02504794e2846c7f955976/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string47 = /2523d17e9fc1b815001f2e7ea951dd3454a78bab0b12cea6a82294b9d93cd95c/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string48 = /2ca71789c452d549809f184185b08febc560b5dc81030586a3920a95ea7a3d12/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string49 = /3887f7179aa36da3d9fc527a714d6f4be500dd25beede1e161e9f019beaf7636/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string50 = /3b2cec2cc3a2e3185fc1797590dc58421cf4382e86d83e8658990bb3979d7209/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string51 = /3f47dae30e9b18dcfd50eef1d188f83171072136257758ea39997818f38d49e8/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string52 = /43861355ea40db311824a51d5a4c6dc773ebfc0c5862a252a4692847f184594c/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string53 = /460acbb38b0bdb3d227de65010b1a323f448ec196860ce4979c0b8314763eb56/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string54 = /4bb2a508148f1895c0371293b6430f18a4083e753e0901dc6257b9d16114f28e/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string55 = /4c9aad477ebdd6bbc57a746b43db4fa1398f4f998e8ebf6e26e10ec5dccb9e68/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string56 = /68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string57 = /70f1ed3ea1ba5d2fe5430735089f03cbce1b85a4c719ad2adc7d1049345f2b6c/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string58 = /77432fd21f975da9215b15efc8e0080345732102f7d57a5d9d57f61faa4dfa20/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string59 = /7777E837\-E7A3\-481B\-8BD2\-4C76F639ECFC/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string60 = /7f68729cb251f5aa9ecba08e57f13c8a258ea3cb3c45e7f99881ca496a639d7e/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string61 = /8365dc72d291194a2b3bd59e36473db7404a219fe999c50dad3d793c3a3178e4/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string62 = /8cec1c5a5e6e7e7a7b2d2991e12587228ed2aa9428b1af003ff68dd6bd6994a4/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string63 = /92f384f789dae517d1da7493322db430f5a7d4a6b7d7b74ca3b075bfac881b15/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string64 = /96fb297f3cba18a95a7228a4853a0641d193859999a5488b0cbae6efe708e89c/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string65 = /a0c293a144cb66f4b07d8bd7d52a489b89c2ff30af9427c399e400bc3d374505/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string66 = /a644c87ef0ae3fda790a705dae60cb7c7d2c1153ea3def2fe6f56a822d2e4e9e/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string67 = /aa530e906b1a52f4f72f7a0c50c1599df651cc4ce38331365d74dff9c51b98fb/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string68 = /aeabd0eed04e87b955809822a4696df781a25ccb649f097a523d1cb4cf93a567/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string69 = /AgentCore\/MeshServer_/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string70 = /alt\.meshcentral\.com/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string71 = /c0b17012581f088528c73adb9f228a99bad35ee0a9f74e1a93e688f95d11080f/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string72 = /c3f35c99bf40d43b4eaa759a92f9a1bc5fc3ddcd0f35d338302a9e88cbdf995a/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string73 = /c75e682dd8f063bd0c151b30095bae8061146928f6d8533ac983280ad2c6effc/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string74 = /cc94b15863602ae52934d4c3c08db27c61c1530a483093b82a1029a41c4fbd60/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string75 = /CE5AD78C\-DBDF\-4D81\-9A69\-41B1DF683115/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string76 = /CE62CBEE\-DAA8\-4E5E\-AAAA\-1F6FC291AB94/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string77 = /d3e630985cb4b429375d79dd506842da176a9cbe4e0afb992c694cab48f3e7ce/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string78 = /d5f1ce259c6bc7d54e2f670d336d7cefa1246ad42bd6c81188f4dafb997a342a/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string79 = /d8445e3bd78bac3cc8f8a3f23b68ab971fb85ff061059f8256e41c6b892374f4/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string80 = /E377F156\-BAED\-4086\-B534\-3CC43164607A/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string81 = /e7e6fcf7d0b2ce3732fbeb5c7e48bb4a2f9f8bbca49ad55d13a57e9abb661481/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string82 = /ff98ae3248a0c2d93b00ec2d426578a3b90aec301883662b8da0fb2a213d60ca/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string83 = /https\:\/\/meshcentral\.com\/login/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string84 = /info\.meshcentral\.com/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string85 = /MESH_AGENT_PORT/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string86 = /MESH_AGENT_STUN_PORT/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string87 = /MeshAgent\sCrash\sDumps/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string88 = /meshagent\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string89 = /meshagent\.js/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string90 = /MeshAgent\.mpkg/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string91 = /meshagent\.pid/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string92 = /meshagent\.service/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string93 = /meshagent\.zip/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string94 = /meshagent_aarch64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string95 = /meshagent_aarch64\-cortex\-a53/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string96 = /meshagent_alpine\-x86\-64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string97 = /meshagent_android\.apk/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string98 = /meshagent_arm/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string99 = /meshagent_arm64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string100 = /meshagent_armhf/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string101 = /meshagent_freebsd_x86\-64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string102 = /meshagent_mips/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string103 = /meshagent_mips24kc/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string104 = /meshagent_mipsel24kc/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string105 = /meshagent_openbsd_x86\-64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string106 = /meshagent_openwrt_x86_64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string107 = /meshagent_osx64\.msh/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string108 = /meshagent_osx64_LaunchDaemon/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string109 = /meshagent_osx\-arm\-64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string110 = /meshagent_osx\-universal\-64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string111 = /meshagent_osx\-x86\-32/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string112 = /meshagent_osx\-x86\-64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string113 = /meshagent_pogo/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string114 = /meshagent_poky/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string115 = /meshagent_poky64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string116 = /meshagent_x86/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string117 = /meshagent_x86\-64/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string118 = /meshagent32\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string119 = /meshagent64\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string120 = /MeshAgent\-Android\-x86/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string121 = /meshagentarm64\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string122 = /MeshAgent\-ChromeOS/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string123 = /MeshAgent\-Linux\-ARM\-PlugPC/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string124 = /MeshAgent\-Linux\-XEN\-x86\-32/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string125 = /MeshAgent\-NodeJS/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string126 = /MeshAgentOSXPackager\.zip/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string127 = /MeshAgent\-WinMinCore\-Console\-x86\-32\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string128 = /MeshAgent\-WinMinCore\-Service\-x86\-64\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string129 = /Meshcentral\s\-\sWebRTC\sSample\sServer/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string130 = /MeshCentral\sHTTP\sserver\sport\s/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string131 = /MeshCentral\sSatellite\scould\snot\screate\sa\s802\.1x\sprofile\sfor\sthis\sdevice/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string132 = /MeshCentral\sServer\sTCP\sports/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string133 = /MeshCentral\sServer\sUDP\sports/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string134 = /meshcentral\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string135 = /meshcentral\.serverstats/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string136 = /MeshCentralAssistant\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string137 = /MeshCentralInstaller\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string138 = /meshcentralinstaller\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string139 = /meshcentral\-plugins\.db/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string140 = /MeshCentralRoot\-/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string141 = /MeshCentralRoot\-a/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string142 = /MeshCentralRouter\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string143 = /MeshCentralServer\.njsproj/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string144 = /meshcentral\-smbios\.db/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string145 = /MeshCmd64\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string146 = /meshcmdService\.run/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string147 = /MeshCmd\-signed\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string148 = /meshcommander\sinstall/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string149 = /meshcommander\sstart/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string150 = /meshcommander\sstop/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string151 = /meshcommander\suninstall/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string152 = /MeshConsole64\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string153 = /MeshConsoleARM64\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string154 = /meshinstall\-initd\.sh/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string155 = /meshinstall\-linux\.sh/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string156 = /MeshService\.exe/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string157 = /rootcert\.meshcentral\.com/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string158 = /swarm\.meshcentral\.com/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string159 = /Uploading\sMeshCommander/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string160 = /wss\:\/\/meshcentral\.com/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshAgent
        $string161 = /Ylianst\/MeshAgent/ nocase ascii wide
        // Description: MeshCentral is a full computer management web site - abused by attackers
        // Reference: https://github.com/Ylianst/MeshCentral
        $string162 = /Ylianst\/MeshCentral/ nocase ascii wide

    condition:
        any of them
}
