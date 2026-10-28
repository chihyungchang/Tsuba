#!/bin/bash
# Inert sample: only mimics the shape of the Bundlore dropper, which cuts data out of its own resource fork at an offset, unzips it with a password into a temporary folder and runs it.
# The copy in the repo has no resource fork (git doesn't keep them); the test only writes fake icon data and a zip header at run time, with no real payload.
cd "$(dirname "$0")"
tail -c +9093 "Install.command/..namedfork/rsrc" | funzip -oZwb > "$TMPDIR/Installer_x"
chmod +x "$TMPDIR/Installer_x" && "$TMPDIR/Installer_x"
