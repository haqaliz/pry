Output assets/pry-demo.gif
Output assets/pry-demo.mp4

Set Shell "zsh"
Set FontSize 16
Set Width 1400
Set Height 760
Set Padding 20
Set Margin 20
Set MarginFill "#0b1116"
Set BorderRadius 10
Set WindowBar "Colorful"
Set Theme "Dracula"
Set TypingSpeed 30ms
Set PlaybackSpeed 1.5
Set LoopOffset 6%

Type "pry --version"
Enter
Sleep 500ms

Type "pry scan tests/fixtures/vulnerable-app --report --out /tmp/pry-demo"
Enter
Sleep 15s

Type "PROOF=$(ls -t /tmp/pry-demo/proofs/*.json | head -1)"
Enter
Type "pry verify-proof $PROOF"
Enter
Sleep 5s
