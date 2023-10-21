rule pyinstaller
{
    meta:
        description = "Detection patterns for the tool 'pyinstaller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyinstaller"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string1 = /\/pyinstaller\// nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string2 = /import\sPyInstaller/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string3 = /install\spyinstaller/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string4 = /pyinstaller\s.*\.py/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string5 = /pyinstaller\.exe/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string6 = /pyinstaller\/tarball/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string7 = /pyinstaller\-script\.py/ nocase ascii wide

    condition:
        any of them
}