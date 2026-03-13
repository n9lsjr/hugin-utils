{
  "targets": [{
    "target_name": "hugin_helpers",
    "sources": ["src/helpers.cc"],
    "include_dirs": [
      "<!@(node -p \"require('node-addon-api').include\")"
    ],
    "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
    "conditions": [
      ["OS=='win'", {
        "msvs_settings": {
          "VCCLCompilerTool": { "Optimization": 2 }
        }
      }],
      ["OS=='mac'", {
        "xcode_settings": {
          "GCC_OPTIMIZATION_LEVEL": "3",
          "MACOSX_DEPLOYMENT_TARGET": "10.15"
        }
      }],
      ["OS=='linux'", {
        "cflags": ["-O3"],
        "cflags_cc": ["-O3"]
      }]
    ]
  }]
}
