rule OSEP_Code_Snippets
{
    meta:
        description = "Detection patterns for the tool 'OSEP-Code-Snippets' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OSEP-Code-Snippets"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string1 = /\s\-o\ssimpleXORencoder/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string2 = /\sPSLessExec\.exe/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string3 = /\ssimpleLoader\.c\s\-z\sexecstack/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string4 = /\/OSEP\-Code\-Snippets\.git/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string5 = /\/PrintSpoofer\.exe/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string6 = /\/PSLessExec\.exe/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string7 = /\/ShInject\.exe/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string8 = /\/tmp\/payload\.bin/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string9 = /\/tmp\/payload\.txt/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string10 = /\\lsass\.dmp/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string11 = /\\MiniDump\.ps1/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string12 = /\\PrintSpoofer\.csproj/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string13 = /\\PrintSpoofer\.exe/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string14 = /\\PSLessExec\.exe/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string15 = /\\ROT\sShellcode\sEncoder\.csproj/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string16 = /\\Shellcode\sProcess\sInjector\.csproj/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string17 = /\\ShInject\.exe/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string18 = /\\simpleXORencoder\.c/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string19 = /\\Windows\\Tasks\\a\.exe/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string20 = /\\windows\\tasks\\bin\.exe/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string21 = /\]\sTriggered\sMeterpreter\soneliner\son\s/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string22 = /\]\sUser\scan\simpersonate\sthe\sfollowing\slogins\:\s/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string23 = /08DBC2BF\-E9F3\-4AE4\-B0CC\-6E9C8767982D/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string24 = /0ac4490e04a65d571cc7b069b5070a4853516300b8ea43bd304ca484bf68c761/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string25 = /12139d47846b3be4267cb079cd73db336c938f111880e23a2f21d19b75921c7b/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string26 = /15c8924d9a1c039c2afaf54c431cda1aa0afd3a2dcf67d88d9cafc3ec89cc21b/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string27 = /1659E645\-27B0\-4AB9\-A10E\-64BA4B801CB0/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string28 = /189219A1\-9A2A\-4B09\-8F69\-6207E9996F94/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string29 = /1df00852a369cbb0fd8934ff0caaa785f9a0e64df8b3c723f67ea0af9bd3f264/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string30 = /24b3db5da23d7a56cfff2480ff4fb63ccb8fad4522c490b4478a22711a3ffa1c/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string31 = /2557d33f3a8599158820c409813b53a521cb3d0993352cd45b75f80eecd33f07/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string32 = /2ecb363e5ff0d146859bb93372e5e00f4fd6fd265bdbe7b5dd36f2716199cc1c/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string33 = /388cab24c7ad1eab00833aa5200541295ba3e17d39d01636f2a8bbb37c732b00/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string34 = /396febb7796a5a3ba0250af4700e9fa21240a83c4ebc2a744da0c2f028ca396c/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string35 = /41a60eed20397bb424a1249da58750b837cb759792e06b66218e825c03c54235/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string36 = /51c1957fed54412620774e2639cd42936d3141bc4c0c84ce6469c578d97e5deb/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string37 = /5751db8dd5b4407b720b3bea4b8e33b560a8f0879318bb3327bd7e4f102af12a/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string38 = /59224C16\-39C5\-49EA\-8525\-F493DC1D66FE/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string39 = /595D5812\-AA30\-4EDE\-95DA\-8EDD7B8844BD/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string40 = /600f564845d4257540556c7dd75333ad0a206c3ce9e88048db23c0ff5396f3f0/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string41 = /612cfb5648987cf92203adf35d73749091458a4e95cba244873bab5a73586fc7/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string42 = /6212badbf494f425f21ff4792c83e272dfa8b7c3352a993aa352e2cbe6d97106/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string43 = /6f4889c2f3d0a774b4bb263ce776d06ead586b813d144ea38b0b9fdabac445d7/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string44 = /6f823ad8cdfce84637bfbbcfc16fcf59f479fb56b735a8fa862096205f559029/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string45 = /7418d1e6a74aea632ed7f6d7310130cea80b8f6e2df0592fa344bae7987d17c9/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string46 = /77F955C3\-4910\-49EA\-9CD4\-CBF5AD9C071A/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string47 = /78434b52f03704cdf214f0497bdef7180741d5d7e40f404970508490c76731ec/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string48 = /7bf796eca83019bad71db3ac9570b92d9f02ce7fa02d2891ef0116cb991fe022/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string49 = /82296b7a1d8b420d648c3ca0aa9f6560d11729d3fb97f534f03afd10a6d6460b/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string50 = /85a5981495372d449656d4da528a0884e3bf06307f0e52756823cd474a687cc6/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string51 = /8ae33d1da163dd41ff4bfe07f9b290d6fa2a46b592735ec9734477534760ea5e/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string52 = /8ebc87ad08296cb20668cd2d4c3a5a5cdd847100f3e5cf559d1b48ebae32959b/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string53 = /94AEDCE4\-D4A2\-45DB\-B98E\-860EE6BE8385/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string54 = /9aae462701ca988bcd44fb093d7edaab28c810b398e349981361ab4a69294827/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string55 = /a06cd42be641036f7d0adb765468209f27d88ce00b8df151a01022461e878bb2/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string56 = /a75a1abcf2235c58fdcd4a6dd7c7347eeec4a094696c255bc8d45026d2c94e6c/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string57 = /a998e3aa58debd0797b430649420e49ca0b1299a005900dfaf17f661facfe039/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string58 = /AppLocker\sBypass\sPowerShell\sRunspace\.csproj/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string59 = /b9e0d24db9c2db196bf5290e2ea67913ba908e69e951c62a89a6e80e90c40a0e/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string60 = /be5cfdd35404d90af8b73a2c53fcc2e2ca3aafb2af4f5484b8aea25f8cb60e73/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string61 = /c85c00d64c49d48f8b3cd34210e4604ac10853758e206bd6f5aa6f9ee2d19b3e/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string62 = /C91C8B29\-82DF\-49C0\-986B\-81182CF84E42/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string63 = /chvancooten\/OSEP\-Code\-Snippets/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string64 = /d49db978a24cbafd9e310593896fb6df6b9360170ca1d80ce99231e02848df6c/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string65 = /d6a875122b65917b00c7afdf247b3e20619b7fdc8622e9a56280912f013e5522/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string66 = /D8B2F4F4\-2B59\-4457\-B710\-F15844570997/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string67 = /dd4543fa5f777ca9ad6ab6bf3d53cc8f186113da38d81159c776b1476eecb5e8/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string68 = /Dumped\sLSASS\smemory\sto\s/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string69 = /E08BAA9C\-9D20\-4C9A\-8933\-EC567F39F54C/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string70 = /e5d6eb36d1fe75a3f558093179a13f0cd74a661397eba1c7a0963200a8a365c0/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string71 = /ec6f110ed955c4659147b008e4e1053b15a873b5bb887662b0685f84d929c44c/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string72 = /EE64B207\-D973\-489B\-84A8\-B718B93E039B/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string73 = /f4ec39cac50227d36423f1384a7144fa4faee9d29879ec5305259a676f46b290/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string74 = /f639c47dde4c4e363129e6b9ca2610cc07c93265b5e47c773dcf54f5f4b08d7c/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string75 = /fa88cbb335f5284f0c23e4182474314ab936ac37a6f0099e7539e2a0e992d255/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string76 = /fda9ab818e038db8e7813ebfc1cdf52d3726c0ea08019b40d8b6088273d1bb07/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string77 = /Fileless\sLateral\sMovement\.csproj/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string78 = /Got\slsass\.exe\sPID\:\s/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string79 = /Injected\!\sCheck\syour\slistener\!/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string80 = /Injection\sdone\!\sCheck\syour\slistener\!/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string81 = /KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgA2ADcALwBjAGgAYQBwAHQAZQByADcALwByAHUAbgAuAHQAeAB0ACcAKQAgAHwAIABJAEUAWAA/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string82 = /PSLessExec\.exe\s/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string83 = /PSRunspace\-InvokeRun\-certutilCoded\.txt/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string84 = /Shellcode\sProcess\sHollowing\.csproj/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string85 = /Shellcode\sProcess\sHollowing\.csproj/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string86 = /Shellcode\sProcess\sInjector\.ps1/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string87 = /shellcodeCrypter\-bin\.py/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string88 = /shellcodeCrypter\-msfvenom\.py/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string89 = /Simple\sShellcode\sRunner\.csproj/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string90 = /Simple\sShellcode\sRunner\.ps1/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string91 = /Simple\sShellcode\sRunner\.vba/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string92 = /windows\/x64\/meterpreter\/reverse_tcp/ nocase ascii wide
        // Description: notable code snippets for Offensive Security's PEN-300 (OSEP) course
        // Reference: https://github.com/chvancooten/OSEP-Code-Snippets
        $string93 = /XOR\sShellcode\sEncoder\.csproj/ nocase ascii wide

    condition:
        any of them
}
