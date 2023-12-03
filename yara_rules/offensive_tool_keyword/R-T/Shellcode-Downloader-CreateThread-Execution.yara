rule Shellcode_Downloader_CreateThread_Execution
{
    meta:
        description = "Detection patterns for the tool 'Shellcode-Downloader-CreateThread-Execution' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shellcode-Downloader-CreateThread-Execution"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This POC gives you the possibility to compile a .exe to completely avoid statically detection by AV/EPP/EDR of your C2-shellcode and download and execute your C2-shellcode which is hosted on your (C2)-webserver.
        // Reference: https://github.com/VirtualAlllocEx/Shellcode-Downloader-CreateThread-Execution
        $string1 = /.{0,1000}Shellcode\-Download_CreateThread_Execution.{0,1000}/ nocase ascii wide
        // Description: This POC gives you the possibility to compile a .exe to completely avoid statically detection by AV/EPP/EDR of your C2-shellcode and download and execute your C2-shellcode which is hosted on your (C2)-webserver.
        // Reference: https://github.com/VirtualAlllocEx/Shellcode-Downloader-CreateThread-Execution
        $string2 = /.{0,1000}Shellcode\-Downloader\-CreateThread\-Execution.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
