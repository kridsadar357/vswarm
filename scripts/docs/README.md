# Screenshots for the guide

`docs/img/*.png` are real vswarm output from a demo machine, regenerated whenever the output changes:

```bash
# 1. record: runs every command in the Linux test container (hostname laptop, user dev, made-up data)
docker build -t vswarm-linux-test scripts/docs
docker run --rm --privileged --hostname laptop -v "$PWD":/src:ro -v /tmp/vswarm-shots:/out \
  vswarm-linux-test bash /src/scripts/docs/scenario.sh

# 2. render: terminal windows as PNG (needs Chrome; ImageMagick shrinks them to 96 colours)
bun scripts/docs/render.ts /tmp/vswarm-shots docs/img
```

`--privileged` lets bubblewrap mount a private `/proc` for the `vswarm try` shots; nothing in the scenario touches the
host. Add a shot by adding a `shot <name> "<command>"` line to `scenario.sh` and an image link in the guides.
