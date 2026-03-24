from PIL import Image
import os

os.makedirs('data/safe', exist_ok=True)

frames = []
colors = [(255, 0, 0), (0, 255, 0), (0, 0, 255)]

for color in colors:
    frame = Image.new('RGB', (100, 100), color=color)
    frames.append(frame)

frames[0].save(
    'data/safe/test_sample.gif',
    save_all=True,
    append_images=frames[1:],
    loop=0,
    duration=200
)
print("Created data/safe/test_sample.gif")