rule demiguise
{
    meta:
        description = "Detection patterns for the tool 'demiguise' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "demiguise"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string1 = /\sdemiguise\.py/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string2 = /\s\-k\s.{0,1000}\s\-c\s.{0,1000}\.exe.{0,1000}\s\-p\sOutlook\.Application\s\-o\s.{0,1000}\.hta/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string3 = /\s\-k\s.{0,1000}\s\-c\s.{0,1000}cmd\.exe\s\/c\s.{0,1000}\s\-o\s.{0,1000}\.hta\s\-p\sShellBrowserWindow/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string4 = /\/demiguise\.py/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string5 = /\\demiguise\.py/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string6 = /nccgroup\/demiguise/ nocase ascii wide
        // Description: The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page. the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place. and (if you use environmental keying) to avoid it being sandboxed.
        // Reference: https://github.com/nccgroup/demiguise
        $string7 = /Yh0Js82rIfFEbS6pR7oUkN0Use54pIZBa3fpYprAMuURNrZZGc6cM8dc\+AC/ nocase ascii wide

    condition:
        any of them
}
