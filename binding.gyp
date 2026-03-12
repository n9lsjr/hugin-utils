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
      ["OS!='win'", {
        "cflags": ["-O3"],
        "cflags_cc": ["-O3"]
      }]
    ]
  }]
}
