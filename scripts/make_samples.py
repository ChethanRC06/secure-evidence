"""Generate real multimedia evidence samples (text, png, jpg, wav, mp3, mp4, pdf) into report/samples/."""
import os, subprocess, sys, wave, struct, math, io
from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "report", "samples")


def ff(*args):
    subprocess.run(["ffmpeg", "-y", "-v", "error", *args], check=True)


def make(out=OUT):
    os.makedirs(out, exist_ok=True)
    p = lambda n: os.path.join(out, n)
    open(p("witness_statement.txt"), "w", encoding="utf-8").write(
        "Witness statement — Case 2026/0417\nI observed the vehicle at 21:40. ✓\n" * 200)
    im = Image.new("RGB", (640, 480), (40, 60, 90)); d = ImageDraw.Draw(im)
    for i in range(0, 640, 40): d.line([(i, 0), (640 - i, 480)], fill=(200, 180, 60), width=2)
    d.text((20, 20), "EVIDENCE PHOTO 0417-A", fill=(255, 255, 255)); im.save(p("crime_scene.png")); im.save(p("crime_scene.jpg"), quality=85)
    with wave.open(p("interview.wav"), "wb") as w:                 # 3 s, 16-bit mono, 440 Hz
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(16000)
        w.writeframes(b"".join(struct.pack("<h", int(12000 * math.sin(2 * math.pi * 440 * t / 16000))) for t in range(48000)))
    ff("-i", p("interview.wav"), "-codec:a", "libmp3lame", "-b:a", "96k", p("voicemail.mp3"))
    ff("-f", "lavfi", "-i", "testsrc=duration=3:size=320x240:rate=15", "-f", "lavfi", "-i", "sine=frequency=600:duration=3",
       "-c:v", "mpeg4", "-c:a", "aac", "-shortest", p("cctv_clip.mp4"))
    im.save(p("report.pdf"), "PDF")                                # simple PDF document
    return sorted(os.listdir(out))


if __name__ == "__main__":
    print(make())
