#!/usr/bin/env python3
"""Optional: convert actual C renderer PBM captures with Pillow."""
from pathlib import Path
from PIL import Image, ImageDraw

captures = Path(__file__).resolve().parent.parent / 'docs/captures'
names = ['menu', 'workflow-start', 'reader-menu', 'workflow-classic', 'workflow-lf', 'lf-results', 'identity', 'log', 'reader-report']
gallery = Image.new('RGB', (1536, 864), '#dddddd')
for index, name in enumerate(names):
    frame = Image.open(captures / f'{name}.pbm').convert('RGB').resize(
        (512, 256), Image.Resampling.NEAREST)
    frame.save(captures / f'{name}.png')
    x, y = (index % 3) * 512, (index // 3) * 288
    gallery.paste(frame, (x, y + 25))
    ImageDraw.Draw(gallery).text((x + 10, y + 5), name, fill='black')
gallery.save(captures / 'gallery.png')
frames = [Image.open(captures / f'{name}.pbm').convert('RGB').resize(
    (512, 256), Image.Resampling.NEAREST)
    for name in ['log', 'log-0', 'log-1', 'log-2', 'log-3']]
frames[0].save(captures / 'scroll.gif', save_all=True,
    append_images=frames[1:] + frames[-2::-1], duration=600, loop=0)
busy = [Image.open(captures / f'busy-{index}.pbm').convert('RGB').resize(
    (512, 256), Image.Resampling.NEAREST) for index in range(16)]
busy[0].save(captures / 'busy.gif', save_all=True,
    append_images=busy[1:], duration=300, loop=0)
print('Updated host C-renderer gallery and GIFs')
