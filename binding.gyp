{
  "targets": [
    {
      "target_name": "quic",
      "sources": [ "src/quic.cc" ],
      "include_dirs": [
        "<(module_root_dir)/src"
      ],
      "msvs_settings": {
        "VCCLCompilerTool": {
          "AdditionalIncludeDirectories": [
            "C:\\vcpkg\\installed\\x64-windows\\include",
            "%(AdditionalIncludeDirectories)"
          ],
          "AdditionalOptions": [
            "/showIncludes"
          ]
        },
        "VCLinkerTool": {
          "AdditionalLibraryDirectories": [
            "C:\\vcpkg\\installed\\x64-windows\\lib",
            "%(AdditionalLibraryDirectories)"
          ]
        }
      },
      "libraries": [
        "C:\\vcpkg\\installed\\x64-windows\\lib\\libssl.lib",
        "C:\\vcpkg\\installed\\x64-windows\\lib\\libcrypto.lib",
        "Ws2_32.lib",
        "Crypt32.lib",
        "Bcrypt.lib"
      ],
      "cflags_cc": [ "-std=c++17" ]
    }
  ]
}