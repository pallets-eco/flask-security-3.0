import blinker

signals = blinker.Namespace()

user_registered = signals.signal("user-registered")

password_reset_requested = signals.signal("password-reset-requested")
