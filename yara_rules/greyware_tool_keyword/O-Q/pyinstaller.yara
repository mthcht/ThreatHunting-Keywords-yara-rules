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
        $string1 = /.{0,1000}\/pyinstaller\/.{0,1000}/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string2 = /.{0,1000}import\sPyInstaller.{0,1000}/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string3 = /.{0,1000}install\spyinstaller.{0,1000}/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string4 = /.{0,1000}pyinstaller\s.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string5 = /.{0,1000}pyinstaller\.exe.{0,1000}/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string6 = /.{0,1000}pyinstaller\/tarball.{0,1000}/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string7 = /.{0,1000}pyinstaller\-script\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
