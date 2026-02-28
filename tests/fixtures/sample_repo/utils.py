"""Utility module — imports PIL (Pillow)."""

from PIL import Image


def resize_image(path, width, height):
    img = Image.open(path)
    return img.resize((width, height))
