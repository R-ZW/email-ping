"""Constantes compartilhadas entre módulos."""

# PNG transparente 1x1, servido por GET /pixel/{token}
TRACKING_PIXEL_PNG = bytes(
    [
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82,
        0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 31, 21, 196,
        137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 156, 99, 248, 255, 255, 63,
        0, 5, 254, 2, 254, 167, 53, 129, 132, 0, 0, 0, 0, 73, 69, 78,
        68, 174, 66, 96, 130,
    ]
)
