#!/bin/sh
# snap.sh DIR — what a move must carry of the working copy in DIR, one line per
# fact, in a form the hub and the device print alike so the two can be diffed:
# HEAD, every branch and tag, the index, every file git does not ignore outside
# .cloop (its digest and executable bit, a link's target, or "missing" for a
# file the index has and the disk does not), and the .cloop files a move
# delivers.
cd "$1" || exit 1
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
echo "HEAD $(git symbolic-ref -q HEAD || echo "detached $(git rev-parse HEAD)")"
git for-each-ref --format='ref %(refname) %(objectname)' refs/heads refs/tags
git ls-files --stage | sed 's/^/index /'
git -c core.quotepath=off ls-files -z -co --exclude-standard | tr '\0' '\n' | grep -v '^\.cloop/' | sort -u |
  while IFS= read -r p; do
    if [ -L "$p" ]; then
      echo "file $p link $(readlink "$p")"
    elif [ -f "$p" ]; then
      m="file"
      [ -x "$p" ] && m="exec"
      echo "file $p $m $(sha256sum <"$p" | cut -d' ' -f1)"
    else
      echo "file $p missing"
    fi
  done
for d in artifacts tasks attachments/outbox checkpoints; do
  [ -d ".cloop/$d" ] && find ".cloop/$d" -type f | sort | while IFS= read -r f; do
    echo "extra ${f#.cloop/} $(sha256sum <"$f" | cut -d' ' -f1)"
  done
done
for f in sandbox.yaml requirements.yaml; do
  [ -f ".cloop/$f" ] && echo "extra $f $(sha256sum <".cloop/$f" | cut -d' ' -f1)"
done
true
