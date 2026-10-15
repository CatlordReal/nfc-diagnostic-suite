#!/usr/bin/env python3
"""Render a fresh gallery/GIFs from this revision's actual C framebuffer captures."""
from pathlib import Path
from PIL import Image, ImageDraw

captures = Path(__file__).resolve().parent.parent / 'docs/captures'
names = ['menu', 'workflow-start', 'card-ready', 'reader-ready', 'busy-0', 'busy-lf', 'busy-reader', 'busy-nfc-reader', 'busy-stopping',
         'card-outcome', 'reader-fields', 'saved-step', 'saved-system-long', 'verify-copy', 'choose-file', 'reread',
         'nonces-waiting', 'nonces-pair', 'nonces-saved', 'saved-menu', 'session-menu', 'reader-menu', 'results', 'log-first', 'log-last']
# Explicit names prevent an older capture from silently becoming release proof.
required = names + [f'log-{index}' for index in range(4)] + [f'busy-{index}' for index in range(16)]
missing = [name for name in required if not (captures / f'{name}.pbm').is_file()]
if missing:
    raise SystemExit('Run tests/render_ui.sh first; missing captures: ' + ', '.join(missing))

def frame(name):
    image = Image.open(captures / f'{name}.pbm')
    if image.size != (128, 64):
        raise SystemExit('Unexpected framebuffer size: ' + name)
    return image.convert('RGB').resize((512, 256), Image.Resampling.NEAREST)

gallery = Image.new('RGB', (1536, ((len(names)+2)//3)*288), '#dddddd')
for index, name in enumerate(names):
    image = frame(name)
    image.save(captures / f'{name}.png')
    x, y = (index % 3)*512, (index // 3)*288
    gallery.paste(image, (x, y+25))
    ImageDraw.Draw(gallery).text((x+10, y+5), name, fill='black')
gallery.save(captures / 'gallery.png')
scroll = [frame(name) for name in ['log-first', 'log-0', 'log-1', 'log-2', 'log-3']]
scroll[0].save(captures / 'scroll.gif', save_all=True,
               append_images=scroll[1:]+scroll[-2::-1], duration=600, loop=0)
busy = [frame(f'busy-{index}') for index in range(16)]
busy[0].save(captures / 'busy.gif', save_all=True, append_images=busy[1:], duration=300, loop=0)
print('Updated host-rendered gallery and GIFs from current C fixtures; no physical LCD claim')
