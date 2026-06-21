local function setup(params)
    workspace("plugin_crashcapture" .. params.bitness .. params.prefix)
        configurations { "Debug", "Release" }
        platforms { "x" .. params.bitness }
        location "build"
        characterset "MBCS"
        staticruntime "on"
        pic "On"

        filter "platforms:x86"
            architecture "x86"
        filter "platforms:x64"
            architecture "x86_64"

        filter "configurations:Debug"
            defines { "DEBUG" }
            symbols "On"
        filter "configurations:Release"
            defines { "NDEBUG" }
            optimize "On"

        project("plugin_crashcapture" .. params.bitness .. params.prefix)
            kind "SharedLib"
            language "C++"
            cppdialect "C++17"

            if params.serverside then
                defines { "INTERFACE_PLUGIN" }
            else
                defines { "INTERFACE_PRELOAD" }
            end

            targetdir ("bin/%{cfg.platform}/%{cfg.buildcfg}")
            objdir ("bin-int/%{prj.name}/%{cfg.platform}/%{cfg.buildcfg}")
            targetname ("plugin_crashcapture" .. params.bitness .. params.prefix)

            files { "src/**.cpp", "src/**.h" }
            includedirs { "src" }

            filter "system:windows"
                systemversion "latest"
                defines { "WIN32", "_WINDOWS", "_CRT_SECURE_NO_WARNINGS" }
                links { "dbghelp" }

            filter "system:linux"
                targetprefix ""
                links { "dl", "pthread" }
                buildoptions { "-fno-omit-frame-pointer" }
                linkoptions { "-Wl,--no-as-needed" }
end

setup { prefix = "_sv", serverside = true,  bitness = "86" }
setup { prefix = "_cl", serverside = false, bitness = "86" }
setup { prefix = "_sv", serverside = true,  bitness = "64" }
setup { prefix = "_cl", serverside = false, bitness = "64" }
