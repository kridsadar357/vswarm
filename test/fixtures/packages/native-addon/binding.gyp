{
  "targets": [
    {
      "target_name": "hash",
      "sources": ["src/hash.cc"],
      "include_dirs": ["<!(node -p \"require('node-addon-api').include_dir\")"],
      "libraries": ["<!@(pkg-config --libs openssl 2>/dev/null || echo '')"]
    }
  ]
}
