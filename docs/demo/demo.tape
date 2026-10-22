# VHS tape for the README demo: https://github.com/charmbracelet/vhs
# Driven by docs/demo/record.sh, which sets HOME to an inert fake profile
# (make-demo-home.sh) and puts a built blastradius on PATH. --no-env keeps the
# recorder's own environment out of the report; the scan shows only SHA-256
# fingerprints, never a secret.

Output docs/demo.gif

Set Shell bash
Set FontSize 12
Set Width 1024
Set Height 1120
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 36ms

Hide
Type "cd ~ && clear"
Enter
Show

Sleep 700ms
Type "# What could a credential stealer walk away with from this laptop?"
Sleep 400ms
Enter
Type "blastradius scan --dir src --no-env --min-severity high"
Sleep 500ms
Enter
Sleep 11s
