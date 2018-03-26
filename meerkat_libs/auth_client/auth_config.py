# These are secret settings for the dev environment and the testing harness.
# Deployment uses a different set of keys.

import os

JWT_PUBLIC_KEY = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDJ05k7jDT1O+polxTsCgAysDXc/GnDk0A4MatA4W8rCFdK3CzQKVPZdIldzW0FenTvGHoh2BN1z+cfB5FioD7s1O1gzE0OYq0xK32175fDWAs40BeCwS8Id2CgCBDbS0F/0jY/XJv9hZilxNDyr8wKP1JLJ0RX9QJXuFQ91EHA8DK0fK2O/l+mKxRGnfwd2G3IEv/6vwZC0dCTASpaPdkQpo0YiQ0ZT6VeqLQ2xRP1cfvZST+A48nMRfTWeBRwNUkfexASftfkAlFuIZmbq6aA31sbH7ujWiV4XDOCr0ju34LhCMDm6dzXVD8j5Ruq9MO39TfYeEuSjCpGtoB6Ps0LyNhElLUAe+8HHkOig+smw5+/+OT/3tSwMenOQtM8B8YClzLSIN70H3SIqIpHf9W8/iuMebGwLkYw5s6F69xCZw9JkmZVlbCg3c0Q1Qv0YnBv7o1N5Ixjw+F/4K5lFeloF7Raj/8kdk71nxw5pG9BMRrwReM4TwkEViGzHoVyqqQEqCJYxPNURANPduKEDpUUPxymkuctv5yn0QNeLim5NXCWIw/nEfPnJtI/islMqt4N1VHFLaKnOaKbs3kVD4wkxv40wLBFrP86N9gRr09o3G67OSEzcv7gLfQfr6r+6p/mdoy4o0qZOXh9D+lMsf+plTD8G5fTw/CEYFL56J9EQw== iers@ubuntu"""

JWT_COOKIE_NAME = "meerkat_jwt"

JWT_ALGORITHM = "RS256"

JWT_HEADER_PREFIX = "Bearer "

AUTH_ROOT = os.environ.get("AUTH_ROOT", "http://nginx/auth")
