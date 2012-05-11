import blinker

signals = blinker.Namespace()

user_registered = signals.signal("user-register")
