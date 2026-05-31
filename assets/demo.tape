# VHS tape for assets/demo.gif
# Render with: vhs assets/demo.tape
# Requires `scc` on PATH; this tape assumes the binary is at /tmp/scc.

Output assets/demo.gif

Set FontSize 18
Set Width 1200
Set Height 740
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set Padding 28
Set Margin 0
Set LineHeight 1.2

Hide
Type "export PATH=/tmp:$PATH && export PS1='$ ' && clear"
Enter
Show

Sleep 800ms
Type "scc id 'spiffe://Example.com/payments/'"
Sleep 500ms
Enter
Sleep 5500ms
