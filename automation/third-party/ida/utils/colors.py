import builtins


def rgb_color(index, imin, imax):
    # color format: 0xBBGGRR
    # The green component is ignore and set to 0 (GG = 0x00)
    percent = float(index - imin) / float(imax - imin)
    blue = int(round((1 - percent) * 0xff)) << 0x10
    red = int(round(percent * 0xff))
    return blue + red


def compute_frequency_colors(frequencies):
    unique_freqs = sorted(set(frequencies))
    imin = 0
    imax = len(unique_freqs) - 1
    colors = builtins.dict()
    for (index, freq) in enumerate(unique_freqs):
        colors[freq] = rgb_color(index, imin, imax)
    return colors
