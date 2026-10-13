#!/bin/zsh
#
# check-manpage.sh — the man page against the command tree, both directions.
#
# Usage: Scripts/check-manpage.sh .build/debug/zhen zhen.1
#
# Written for stage M of the CLI-v1 run. Its first version measured nothing useful: it read
# a wrapped help line as a subcommand ("happened") and compared `-check` with `--check`,
# so every flag looked foreign. Shown failing on a page with options removed and an
# invented `--udp` added before it was trusted; see Docs/process/V6-progress.md, stage M.
# Every option each subcommand's --help lists must be in the man page, and every
# option the man page names must be one some command accepts. Case-sensitive on
# purpose: flags are case-sensitive. Reads the page's `Fl -name` macros, not prose.
Z=$1; MAN=$2; fail=0
subs=$($Z --help | sed -n '/SUBCOMMANDS:/,/See/p' | grep -E '^  [a-z]+( \(default\))? {2,}' | awk '{print $1}')
[ -z "$subs" ] && { echo "no subcommands parsed — the check measures nothing"; exit 2; }
accepted=()
for c in ${=subs}; do
  flags=$($Z help $c 2>&1 | grep -oE '^\s+--[a-z-]+' | tr -d ' ' | grep -vE '^--(help|version)$' | sort -u)
  n=0
  for f in ${=flags}; do
    n=$((n+1)); accepted+=$f
    grep -qE "Fl -${f#--}( |$)" $MAN || { echo "MISSING from page: $c $f"; fail=1; }
  done
  grep -qE "^\.Cm $c( |$)|^\.It Cm $c( |$)" $MAN || { echo "MISSING command: $c"; fail=1; }
  echo "  $c: $n options checked"
done
for f in $(grep -oE 'Fl -[a-z-]+' $MAN | sed 's/Fl /-/' | sort -u); do
  (( ${accepted[(Ie)$f]} )) || { echo "ON PAGE BUT ACCEPTED BY NO COMMAND: $f"; fail=1; }
done
echo "subcommands: $(echo $subs | wc -w | tr -d ' '), result: $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
